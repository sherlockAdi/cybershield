package main

import (
	"errors"
	"io"
	"os"
)

func readPrivateFile(filename string, limit int64) ([]byte, error) {
	before, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > limit {
		return nil, errors.New("expected a bounded private regular file")
	}
	file, err := openPrivateDescriptor(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 || !os.SameFile(before, after) {
		return nil, errors.New("private file changed during open")
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, errors.New("private file exceeds size limit")
	}
	return content, nil
}
