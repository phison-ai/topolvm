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

// Package agent runs on every aiDAPTIV node. It resolves the NVMe disks that
// back a volume group and runs the Sails check tool against them on behalf of
// the attester.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/topolvm/topolvm/internal/attester/config"
)

// DefaultSysClassBlock is where the kernel exposes block devices.
const DefaultSysClassBlock = "/sys/class/block"

// DefaultLVMCommandPrefix runs LVM in the host namespaces (the DaemonSet sets
// hostPID), so the host's lvm2 and its devices file are used and the agent
// image needs no lvm2 of its own.
var DefaultLVMCommandPrefix = []string{"nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--"}

// Result is what one check returns.
// Report is what the agent attests to the attester: the Result plus what
// binds it to one request and one node.
type Report struct {
	// Use is attest.UseAgentResult.
	Use string `json:"use"`
	// Nonce is the attester's nonce for this request, echoed back.
	Nonce    string `json:"nonce"`
	IssuedAt int64  `json:"iat"`
	// Node is the node the agent runs on.
	Node string `json:"node"`
	// Function is the Sails function that ran.
	Function string `json:"fn"`
	Result
}

type Result struct {
	// VolumeGroup is the LVM volume group that was checked.
	VolumeGroup string `json:"volume_group"`
	// PhysicalVolumes are the PV device paths of the volume group, e.g.
	// ["/dev/md127"].
	PhysicalVolumes []string `json:"physical_volumes"`
	// Disks are the whole disks behind the PVs, e.g. ["/dev/nvme0n1", ...].
	Disks []string `json:"disks"`
	// Results holds one {"<disk name>": "<Sails output>"} per disk, in the
	// format cache-operator clients already parse.
	Results []map[string]string `json:"results"`
}

// ExecFunc runs a command and returns stdout, stderr and the exit error. It is
// a field of Checker so tests can substitute a fake.
type ExecFunc func(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)

// Checker finds the disks of a volume group and runs Sails against them.
type Checker struct {
	// Sails is the path of the Sails binary.
	Sails string
	// LVMCommandPrefix is prepended to every LVM command.
	LVMCommandPrefix []string
	// SysClassBlock is the sysfs directory used to resolve backing disks.
	SysClassBlock string
	// Timeout bounds one whole check (pvs plus Sails).
	Timeout time.Duration
	// Exec runs commands; nil means os/exec.
	Exec ExecFunc

	// Sails issues vendor-unique commands to the drives; two at once on the
	// same drive is asking for trouble, so checks are serialized.
	mu sync.Mutex
}

// Run checks every disk behind vg with the Sails function fn.
func (c *Checker) Run(ctx context.Context, fn, vg string) (*Result, error) {
	if !config.IsCheckFunction(fn) {
		return nil, fmt.Errorf("unknown check function %q", fn)
	}
	if vg == "" {
		return nil, errors.New("volume group is empty")
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	pvs, err := c.listPhysicalVolumes(ctx, vg)
	if err != nil {
		return nil, err
	}
	if len(pvs) == 0 {
		return nil, fmt.Errorf("volume group %s has no physical volume (does it exist on this node?)", vg)
	}

	sysClassBlock := c.SysClassBlock
	if sysClassBlock == "" {
		sysClassBlock = DefaultSysClassBlock
	}
	var disks []string
	seen := map[string]bool{}
	for _, pv := range pvs {
		backing, err := BackingDisks(sysClassBlock, pv)
		if err != nil {
			return nil, fmt.Errorf("resolve backing disks of %s: %w", pv, err)
		}
		for _, d := range backing {
			if !seen[d] {
				seen[d] = true
				disks = append(disks, d)
			}
		}
	}
	log.FromContext(ctx).V(1).Info("resolved backing disks", "volumeGroup", vg, "pvs", pvs, "disks", disks)

	results, err := c.runSails(ctx, fn, disks)
	if err != nil {
		return nil, err
	}
	return &Result{VolumeGroup: vg, PhysicalVolumes: pvs, Disks: disks, Results: results}, nil
}

// listPhysicalVolumes returns the pv_name of every PV in vg.
func (c *Checker) listPhysicalVolumes(ctx context.Context, vg string) ([]string, error) {
	prefix := c.LVMCommandPrefix
	if prefix == nil {
		prefix = DefaultLVMCommandPrefix
	}
	words := append(append([]string{}, prefix...),
		"pvs", "-o", "pv_name", "--select", "vg_name="+vg, "--reportformat", "json")
	stdout, stderr, err := c.exec(ctx, words[0], words[1:]...)
	if err != nil {
		return nil, fmt.Errorf("pvs: %w (stderr: %s)", err, strings.TrimSpace(string(stderr)))
	}
	return parsePVSReport(stdout)
}

func parsePVSReport(out []byte) ([]string, error) {
	var report struct {
		Report []struct {
			PV []struct {
				Name string `json:"pv_name"`
			} `json:"pv"`
		} `json:"report"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("parse pvs output: %w", err)
	}
	var paths []string
	for _, r := range report.Report {
		for _, pv := range r.PV {
			if pv.Name != "" {
				paths = append(paths, pv.Name)
			}
		}
	}
	return paths, nil
}

// runSails runs `Sails <fn> <name>,<name>,...`. Sails wants device names
// without /dev/ and reports its verdict on stdout, so a non-zero exit with
// output is still parsed.
func (c *Checker) runSails(ctx context.Context, fn string, disks []string) ([]map[string]string, error) {
	names := make([]string, 0, len(disks))
	for _, d := range disks {
		names = append(names, strings.TrimPrefix(d, "/dev/"))
	}
	stdout, stderr, err := c.exec(ctx, c.Sails, fn, strings.Join(names, ","))
	if err != nil && len(bytes.TrimSpace(stdout)) == 0 {
		return nil, fmt.Errorf("run %s %s: %w (stderr: %s)", c.Sails, fn, err, strings.TrimSpace(string(stderr)))
	}
	results := ParseSailsOutput(string(stdout))
	if len(results) == 0 {
		return nil, fmt.Errorf("%s %s produced no parseable output: %q", c.Sails, fn, string(stdout))
	}
	return results, nil
}

func (c *Checker) exec(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	if c.Exec != nil {
		return c.Exec(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// sailsFailure matches the line Sails prints when a function raises:
// "Run <fn> on <dev> failed: <message>".
var sailsFailure = regexp.MustCompile(`^Run \S+ on (\S+) failed: (.*)$`)

// ParseSailsOutput turns Sails stdout ("<dev>: <value>" per line) into one map
// per device, the format cache-operator clients already parse:
// [{"nvme0n1":"1"},{"nvme1n1":"0"}]. A failure line becomes
// {"<dev>":"error: <message>"}.
func ParseSailsOutput(output string) []map[string]string {
	var result []map[string]string
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := sailsFailure.FindStringSubmatch(line); m != nil {
			result = append(result, map[string]string{m[1]: "error: " + strings.TrimSpace(m[2])})
			continue
		}
		dev, val := line, ""
		if idx := strings.Index(line, ":"); idx >= 0 {
			dev, val = strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
		} else if idx := strings.Index(line, " "); idx >= 0 {
			dev, val = strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
		}
		if dev != "" {
			result = append(result, map[string]string{dev: val})
		}
	}
	return result
}
