package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func lockState(directory string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(directory, "agent.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another agent owns this state directory")
	}
	return func() { syscall.Flock(int(file.Fd()), syscall.LOCK_UN); file.Close() }, nil
}
