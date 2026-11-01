package main

import (
	"os"
	"syscall"
)

func openPrivateDescriptor(filename string) (*os.File, error) {
	descriptor, err := syscall.Open(filename, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), filename), nil
}
