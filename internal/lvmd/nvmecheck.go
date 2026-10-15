package lvmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/topolvm/topolvm/internal/lvmd/command"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Result values printed by the NVMe VUC check tool on stdout (format
// "<device>: <N>").
const (
	// nvmeCheckUnsupported means the device does not support the feature.
	nvmeCheckUnsupported = 0
	// nvmeCheckSupported means the device supports the feature and the
	// operation may proceed.
	nvmeCheckSupported = 1

	// nvmeCheckMaxAttempts is how many times a device may be checked while it
	// keeps yielding a non-supported result before the checker gives up and
	// stops invoking the tool (serving the cached failure instead). Restart
	// lvmd to reset and re-check.
	nvmeCheckMaxAttempts = 3

	// defaultSysClassBlock is where the kernel exposes block devices; it is
	// used to walk from a physical volume (e.g. an md RAID array) down to the
	// disks backing it.
	defaultSysClassBlock = "/sys/class/block"

	// maxBackingDiskDepth bounds the walk through stacked block devices
	// (e.g. dm-crypt on md on partitions) to guard against sysfs loops.
	maxBackingDiskDepth = 16
)

// nvmeCheckEntry is the cached per-device state.
type nvmeCheckEntry struct {
	// supported is set once the device passed the check; further operations
	// skip the tool entirely.
	supported bool
	// attempts counts consecutive non-supported checks so far.
	attempts int
	// final is set after attempts reached nvmeCheckMaxAttempts; the tool is no
	// longer invoked and finalErr is returned directly.
	final    bool
	finalErr error
}

// nvmeChecker runs the external NVMe support-check tool per device and caches
// the outcome:
//   - a supported device is cached and never re-checked (until lvmd restart);
//   - a device that keeps failing is re-checked up to maxAttempts times (once
//     per volume operation, i.e. spaced by the external-provisioner's retry
//     backoff); after that it is marked final and the tool is no longer run.
type nvmeChecker struct {
	cmd         []string
	maxAttempts int
	// run performs a single check for one device; nil error means supported.
	// It is a field so tests can substitute a fake.
	run func(ctx context.Context, cmd []string, device string) error
	// sysClassBlock is the sysfs directory used to resolve backing disks.
	// It is a field so tests can point it at a fake tree.
	sysClassBlock string

	mu    sync.Mutex
	cache map[string]*nvmeCheckEntry
}

// newNVMeChecker returns a checker for the given command, or nil if the check
// is disabled (empty command).
func newNVMeChecker(cmd []string) *nvmeChecker {
	if len(cmd) == 0 {
		return nil
	}
	return &nvmeChecker{
		cmd:           cmd,
		maxAttempts:   nvmeCheckMaxAttempts,
		run:           runNVMeCheckDevice,
		sysClassBlock: defaultSysClassBlock,
		cache:         map[string]*nvmeCheckEntry{},
	}
}

// check verifies a single device, applying the cache and retry policy.
func (c *nvmeChecker) check(ctx context.Context, device string) error {
	logger := log.FromContext(ctx)

	c.mu.Lock()
	entry := c.cache[device]
	if entry == nil {
		entry = &nvmeCheckEntry{}
		c.cache[device] = entry
	}
	switch {
	case entry.supported:
		c.mu.Unlock()
		return nil
	case entry.final:
		err := entry.finalErr
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()

	err := c.run(ctx, c.cmd, device)

	c.mu.Lock()
	defer c.mu.Unlock()

	if err == nil {
		entry.supported = true
		entry.attempts = 0
		logger.Info("NVMe check passed; caching device as supported", "device", device)
		return nil
	}

	entry.attempts++
	if c.maxAttempts > 0 && entry.attempts >= c.maxAttempts {
		entry.final = true
		entry.finalErr = status.Errorf(status.Code(err),
			"%s (giving up after %d failed NVMe checks; restart lvmd to re-check)",
			status.Convert(err).Message(), entry.attempts)
		logger.Error(err, "NVMe check failed; giving up and blocking this device until lvmd restarts",
			"device", device, "attempts", entry.attempts, "max_attempts", c.maxAttempts)
		return entry.finalErr
	}

	logger.Error(err, "NVMe check failed; will retry on the next volume operation",
		"device", device, "attempts", entry.attempts, "max_attempts", c.maxAttempts)
	return err
}

// backingDisks returns the whole disks (e.g. ["/dev/nvme0n1", "/dev/nvme1n1"])
// underneath a physical volume device path. Stacked devices such as md RAID
// arrays, device-mapper targets and partitions are resolved through sysfs:
//   - a device with entries in "slaves/" is replaced by those slaves;
//   - a partition (has a "partition" file) is replaced by its parent disk;
//   - anything else is a whole disk and is returned as is.
//
// If the device is not found in sysfs, it is returned unchanged so the check
// still runs against it.
func (c *nvmeChecker) backingDisks(ctx context.Context, devicePath string) ([]string, error) {
	logger := log.FromContext(ctx)

	// Resolve symlinks such as /dev/mapper/foo -> /dev/dm-0 or
	// /dev/md/name -> /dev/md127 to get the kernel device name.
	name := filepath.Base(devicePath)
	if resolved, err := filepath.EvalSymlinks(devicePath); err == nil {
		name = filepath.Base(resolved)
	}

	if _, err := os.Stat(filepath.Join(c.sysClassBlock, name)); err != nil {
		logger.Info("block device not found in sysfs; checking it directly",
			"device", devicePath, "sysfs", c.sysClassBlock, "error", err.Error())
		return []string{devicePath}, nil
	}

	var disks []string
	seen := map[string]bool{}
	if err := c.walkBackingDisks(name, 0, seen, &disks); err != nil {
		return nil, err
	}
	if len(disks) == 0 {
		return nil, fmt.Errorf("no backing disk found for %s", devicePath)
	}
	if len(disks) != 1 || disks[0] != "/dev/"+name {
		logger.Info("resolved backing disks for physical volume", "device", devicePath, "disks", disks)
	}
	return disks, nil
}

func (c *nvmeChecker) walkBackingDisks(name string, depth int, seen map[string]bool, disks *[]string) error {
	if depth > maxBackingDiskDepth {
		return fmt.Errorf("block device stack too deep at %s", name)
	}
	dir := filepath.Join(c.sysClassBlock, name)

	slaves, err := os.ReadDir(filepath.Join(dir, "slaves"))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read slaves of %s: %w", name, err)
	}
	if len(slaves) > 0 {
		for _, s := range slaves {
			if err := c.walkBackingDisks(s.Name(), depth+1, seen, disks); err != nil {
				return err
			}
		}
		return nil
	}

	if _, err := os.Stat(filepath.Join(dir, "partition")); err == nil {
		// In sysfs a partition lives inside its parent disk's directory,
		// e.g. .../nvme0n1/nvme0n1p1.
		parentPath, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return fmt.Errorf("failed to resolve sysfs path of %s: %w", name, err)
		}
		return c.walkBackingDisks(filepath.Base(filepath.Dir(parentPath)), depth+1, seen, disks)
	}

	if !seen[name] {
		seen[name] = true
		*disks = append(*disks, "/dev/"+name)
	}
	return nil
}

// runNVMeCheckDevice runs `cmd[0] cmd[1:]... <name>` once and parses the
// trailing integer N from the tool's stdout (format "<name>: <N>").
//
// The device name is passed WITHOUT the leading "/dev/" (the Sails tool rejects
// a "/dev/"-prefixed argument), e.g. "/dev/nvme0n1" is passed as "nvme0n1".
//
//	N == 1 (supported)                               -> nil
//	N == 0 (unsupported)                             -> codes.FailedPrecondition
//	any other N / unparseable stdout / spawn failure -> codes.Internal
func runNVMeCheckDevice(ctx context.Context, cmd []string, device string) error {
	logger := log.FromContext(ctx)

	name := strings.TrimPrefix(device, "/dev/")
	args := append(append([]string{}, cmd[1:]...), name)
	out, err := exec.CommandContext(ctx, cmd[0], args...).Output()
	if err != nil {
		// The tool reports its verdict on stdout, so a non-zero exit does not
		// necessarily mean failure. Only bail out here if we could not run the
		// tool at all or it produced no stdout to parse.
		stderr := ""
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr = string(exitErr.Stderr)
		}
		if len(out) == 0 {
			logger.Error(err, "failed to run NVMe check command", "command", cmd, "device", device, "stderr", stderr)
			return status.Errorf(codes.Internal, "failed to run NVMe check command %v for device %s: %v", cmd, device, err)
		}
		logger.Info("NVMe check command exited non-zero but produced output; parsing stdout",
			"command", cmd, "device", device, "stderr", stderr, "error", err.Error())
	}

	result, perr := parseNVMeCheckOutput(out)
	if perr != nil {
		logger.Error(perr, "failed to parse NVMe check output", "command", cmd, "device", device, "output", string(out))
		return status.Errorf(codes.Internal, "failed to parse NVMe check output for device %s: %v (output: %q)", device, perr, string(out))
	}

	switch result {
	case nvmeCheckSupported:
		return nil
	case nvmeCheckUnsupported:
		return status.Errorf(codes.FailedPrecondition, "NVMe device %s does not support this feature", device)
	default:
		return status.Errorf(codes.Internal, "NVMe check command returned unexpected result %d for device %s", result, device)
	}
}

// parseNVMeCheckOutput extracts the trailing integer from the tool's stdout.
// The output is expected to look like "<device>: <N>"; the integer after the
// last colon on the last non-empty line is returned.
func parseNVMeCheckOutput(out []byte) (int, error) {
	var lastLine string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			lastLine = line
		}
	}
	if lastLine == "" {
		return 0, status.Error(codes.Internal, "empty output")
	}

	field := lastLine
	if idx := strings.LastIndex(lastLine, ":"); idx >= 0 {
		field = lastLine[idx+1:]
	}
	field = strings.TrimSpace(field)

	n, err := strconv.Atoi(field)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// checkNVMe resolves the physical volume device paths backing the given volume
// group, walks them down to the underlying disks (e.g. the members of an md
// RAID array) and runs the NVMe VUC check against each disk. It is a no-op when the check
// is not configured.
func (s *lvService) checkNVMe(ctx context.Context, vgName string) error {
	if s.nvmeChecker == nil {
		return nil
	}
	vg, err := command.FindVolumeGroup(ctx, vgName)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to find volume group %s for NVMe check: %v", vgName, err)
	}
	devicePaths, err := vg.ListPhysicalVolumes(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to list physical volumes for volume group %s: %v", vgName, err)
	}
	if len(devicePaths) == 0 {
		return status.Errorf(codes.Internal, "NVMe check: no physical volume device found for volume group %s", vgName)
	}
	for _, pv := range devicePaths {
		disks, err := s.nvmeChecker.backingDisks(ctx, pv)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to resolve backing disks of physical volume %s: %v", pv, err)
		}
		for _, disk := range disks {
			if err := s.nvmeChecker.check(ctx, disk); err != nil {
				return err
			}
		}
	}
	return nil
}
