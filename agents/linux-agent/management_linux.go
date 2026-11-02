package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validateHelper(filename string) error {
	if !filepath.IsAbs(filename) {
		return fmt.Errorf("management helper must have an absolute path")
	}
	for current := filepath.Clean(filename); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("management helper and parents must be root-owned, non-symlink and not group/world writable")
		}
		if current == "/" {
			break
		}
	}
	return nil
}
