/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseSailsOutput(t *testing.T) {
	cases := map[string]struct {
		in   string
		want []map[string]string
	}{
		"two devices": {
			in:   "nvme0n1: 1\nnvme1n1: 0\n",
			want: []map[string]string{{"nvme0n1": "1"}, {"nvme1n1": "0"}},
		},
		"failure line": {
			in:   "nvme0n1: 1\nRun support_inference on nvme1n1 failed: device busy\n",
			want: []map[string]string{{"nvme0n1": "1"}, {"nvme1n1": "error: device busy"}},
		},
		"space separated": {
			in:   "nvme0n1 EIFZ61.5",
			want: []map[string]string{{"nvme0n1": "EIFZ61.5"}},
		},
		"bare word": {
			in:   "\n  nvme0n1 \n",
			want: []map[string]string{{"nvme0n1": ""}},
		},
		"empty": {in: "  \n", want: nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ParseSailsOutput(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseSailsOutput(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// fakeSysfs builds a /sys/class/block look-alike:
//
//	md127         slaves/nvme0n1, slaves/nvme1n1   (RAID 0 over two disks)
//	nvme0n1, nvme1n1                               whole disks
//	nvme2n1                                        whole disk with partition nvme2n1p1
//	dm-0          slaves/nvme2n1p1                 LVM/dm-crypt on the partition
func fakeSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	devices := filepath.Join(root, "devices")
	class := filepath.Join(root, "class", "block")
	mk := func(parts ...string) string {
		p := filepath.Join(parts...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(target, name string) {
		if err := os.Symlink(target, filepath.Join(class, name)); err != nil {
			t.Fatal(err)
		}
	}
	mk(class)
	for _, d := range []string{"nvme0n1", "nvme1n1", "nvme2n1", "md127", "dm-0"} {
		link(mk(devices, d), d)
	}
	for _, s := range []string{"nvme0n1", "nvme1n1"} {
		mk(devices, "md127", "slaves", s)
	}
	part := mk(devices, "nvme2n1", "nvme2n1p1")
	if err := os.WriteFile(filepath.Join(part, "partition"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link(part, "nvme2n1p1")
	mk(devices, "dm-0", "slaves", "nvme2n1p1")
	return class
}

func TestBackingDisks(t *testing.T) {
	sys := fakeSysfs(t)
	dev := t.TempDir()
	// /dev/md/aidaptiv -> /dev/md127, as mdadm names it.
	if err := os.WriteFile(filepath.Join(dev, "md127"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dev, "md"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../md127", filepath.Join(dev, "md", "aidaptiv")); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		device string
		want   []string
	}{
		"raid array":      {"/dev/md127", []string{"/dev/nvme0n1", "/dev/nvme1n1"}},
		"raid by symlink": {filepath.Join(dev, "md", "aidaptiv"), []string{"/dev/nvme0n1", "/dev/nvme1n1"}},
		"whole disk":      {"/dev/nvme0n1", []string{"/dev/nvme0n1"}},
		"partition":       {"/dev/nvme2n1p1", []string{"/dev/nvme2n1"}},
		"dm on partition": {"/dev/dm-0", []string{"/dev/nvme2n1"}},
		"not in sysfs":    {"/dev/sdz", []string{"/dev/sdz"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := BackingDisks(sys, tc.device)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("BackingDisks(%s) = %v, want %v", tc.device, got, tc.want)
			}
		})
	}
}

const pvsReport = `{"report":[{"pv":[{"pv_name":"/dev/md127"}]}]}`

// fakeExec answers pvs with pvs and Sails with sails; it records every call.
type fakeExec struct {
	pvs, sails         string
	sailsStderr        string
	sailsErr, pvsErr   error
	calls              [][]string
	unexpectedCommands []string
}

func (f *fakeExec) run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	all := strings.Join(append([]string{name}, args...), " ")
	switch {
	case strings.Contains(all, " pvs ") || strings.HasPrefix(all, "pvs "):
		return []byte(f.pvs), nil, f.pvsErr
	case name == "/shared/Sails":
		return []byte(f.sails), []byte(f.sailsStderr), f.sailsErr
	}
	f.unexpectedCommands = append(f.unexpectedCommands, all)
	return nil, nil, errors.New("unexpected command " + all)
}

func newChecker(t *testing.T, fe *fakeExec) *Checker {
	t.Helper()
	return &Checker{
		Sails:            "/shared/Sails",
		LVMCommandPrefix: []string{"nsenter", "-t", "1", "-m", "--"},
		SysClassBlock:    fakeSysfs(t),
		Exec:             fe.run,
	}
}

func TestCheckerRun(t *testing.T) {
	fe := &fakeExec{pvs: pvsReport, sails: "nvme0n1: 1\nnvme1n1: 1\n"}
	c := newChecker(t, fe)

	res, err := c.Run(context.Background(), "support_inference", "vg_aidaptiv")
	if err != nil {
		t.Fatal(err)
	}
	want := &Result{
		VolumeGroup:     "vg_aidaptiv",
		PhysicalVolumes: []string{"/dev/md127"},
		Disks:           []string{"/dev/nvme0n1", "/dev/nvme1n1"},
		Results:         []map[string]string{{"nvme0n1": "1"}, {"nvme1n1": "1"}},
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("Run = %+v, want %+v", res, want)
	}
	if len(fe.calls) != 2 {
		t.Fatalf("calls = %v", fe.calls)
	}
	pvsCall := strings.Join(fe.calls[0], " ")
	if !strings.HasPrefix(pvsCall, "nsenter -t 1 -m -- pvs ") || !strings.Contains(pvsCall, "vg_name=vg_aidaptiv") ||
		!strings.Contains(pvsCall, "--reportformat json") {
		t.Errorf("pvs call = %q", pvsCall)
	}
	// Sails gets the device names without /dev/, comma separated, in one run.
	if got := fe.calls[1]; !reflect.DeepEqual(got, []string{"/shared/Sails", "support_inference", "nvme0n1,nvme1n1"}) {
		t.Errorf("Sails call = %v", got)
	}
}

func TestCheckerRunErrors(t *testing.T) {
	t.Run("unknown function", func(t *testing.T) {
		c := newChecker(t, &fakeExec{})
		if _, err := c.Run(context.Background(), "rm_rf", "vg"); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("empty volume group", func(t *testing.T) {
		c := newChecker(t, &fakeExec{})
		if _, err := c.Run(context.Background(), "support_inference", ""); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("no physical volume", func(t *testing.T) {
		c := newChecker(t, &fakeExec{pvs: `{"report":[{"pv":[]}]}`})
		_, err := c.Run(context.Background(), "support_inference", "vg_none")
		if err == nil || !strings.Contains(err.Error(), "no physical volume") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("pvs fails", func(t *testing.T) {
		c := newChecker(t, &fakeExec{pvsErr: errors.New("exit status 5")})
		if _, err := c.Run(context.Background(), "support_inference", "vg"); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("sails fails without output", func(t *testing.T) {
		fe := &fakeExec{pvs: pvsReport, sailsErr: errors.New("exit status 1"), sailsStderr: "cannot open shared object"}
		c := newChecker(t, fe)
		_, err := c.Run(context.Background(), "mem_buf_set", "vg_aidaptiv")
		if err == nil || !strings.Contains(err.Error(), "cannot open shared object") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("sails non-zero exit with output is parsed", func(t *testing.T) {
		fe := &fakeExec{pvs: pvsReport, sails: "nvme0n1: 0\nnvme1n1: 0\n", sailsErr: errors.New("exit status 1")}
		c := newChecker(t, fe)
		res, err := c.Run(context.Background(), "support_finetune", "vg_aidaptiv")
		if err != nil {
			t.Fatal(err)
		}
		if want := []map[string]string{{"nvme0n1": "0"}, {"nvme1n1": "0"}}; !reflect.DeepEqual(res.Results, want) {
			t.Errorf("results = %v", res.Results)
		}
	})
}
