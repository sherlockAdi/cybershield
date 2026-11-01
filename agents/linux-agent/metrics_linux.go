package main

import "syscall"

func diskUsage() (*int64, *int64) {
	var statistics syscall.Statfs_t
	if err := syscall.Statfs("/", &statistics); err != nil || statistics.Bsize <= 0 || statistics.Blocks > uint64(maxSequence)/uint64(statistics.Bsize) || statistics.Bavail > statistics.Blocks {
		return nil, nil
	}
	total := int64(statistics.Blocks) * statistics.Bsize
	available := int64(statistics.Bavail) * statistics.Bsize
	if total <= 0 {
		return nil, nil
	}
	used := total - available
	return &total, &used
}
