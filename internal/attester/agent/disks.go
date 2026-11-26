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
	"fmt"
	"os"
	"path/filepath"
)

// maxBackingDiskDepth bounds the walk through stacked block devices (e.g.
// dm-crypt on md on partitions) to guard against sysfs loops.
const maxBackingDiskDepth = 16

// BackingDisks returns the whole disks (e.g. /dev/nvme0n1, /dev/nvme1n1)
// underneath a physical volume device path, resolved through sysfs the same
// way TopoLVM's nvme check does:
//   - a device with entries in "slaves/" is replaced by those slaves (md
//     RAID, device-mapper);
//   - a partition (has a "partition" file) is replaced by its parent disk;
//   - anything else is a whole disk and is returned as is.
//
// A device that is not in sysfs is returned unchanged so it is still checked.
func BackingDisks(sysClassBlock, devicePath string) ([]string, error) {
	// /dev/md/aidaptiv -> /dev/md127, /dev/mapper/x -> /dev/dm-0.
	name := filepath.Base(devicePath)
	if resolved, err := filepath.EvalSymlinks(devicePath); err == nil {
		name = filepath.Base(resolved)
	}
	if _, err := os.Stat(filepath.Join(sysClassBlock, name)); err != nil {
		return []string{devicePath}, nil
	}

	var disks []string
	seen := map[string]bool{}
	if err := walkBackingDisks(sysClassBlock, name, 0, seen, &disks); err != nil {
		return nil, err
	}
	if len(disks) == 0 {
		return nil, fmt.Errorf("no backing disk found for %s", devicePath)
	}
	return disks, nil
}

func walkBackingDisks(sysClassBlock, name string, depth int, seen map[string]bool, disks *[]string) error {
	if depth > maxBackingDiskDepth {
		return fmt.Errorf("block device stack too deep at %s", name)
	}
	dir := filepath.Join(sysClassBlock, name)

	slaves, err := os.ReadDir(filepath.Join(dir, "slaves"))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read slaves of %s: %w", name, err)
	}
	if len(slaves) > 0 {
		for _, s := range slaves {
			if err := walkBackingDisks(sysClassBlock, s.Name(), depth+1, seen, disks); err != nil {
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
			return fmt.Errorf("resolve sysfs path of %s: %w", name, err)
		}
		return walkBackingDisks(sysClassBlock, filepath.Base(filepath.Dir(parentPath)), depth+1, seen, disks)
	}

	if !seen[name] {
		seen[name] = true
		*disks = append(*disks, "/dev/"+name)
	}
	return nil
}
