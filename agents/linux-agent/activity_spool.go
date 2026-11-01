package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func queueActivitySpool(state *agentState, directory string) error {
	if directory == "" || state.ImportedEventFile != "" {
		return nil
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("activity spool must be a private directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) > 512 {
		return errors.New("activity spool capacity exceeded")
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		if filepath.Base(name) != name || len(name) > 128 {
			return errors.New("invalid activity spool filename")
		}
		content, err := readPrivateFile(filepath.Join(directory, name), 32768)
		if err != nil {
			return err
		}
		previous := len(state.PendingEvents)
		oldHash := state.ImportedEventsHash
		state.ImportedEventsHash = ""
		if err = importEventBytes(state, content); err != nil {
			state.ImportedEventsHash = oldHash
			return err
		}
		if len(state.PendingEvents) == previous {
			state.ImportedEventsHash = oldHash
			return nil
		}
		state.ImportedEventFile = name
		return nil
	}
	return nil
}

func acknowledgeActivitySpool(state *agentState, directory string) error {
	if state.ImportedEventFile == "" {
		return nil
	}
	name := state.ImportedEventFile
	if directory == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return errors.New("invalid persisted spool receipt")
	}
	filename := filepath.Join(directory, name)
	content, err := readPrivateFile(filename, 32768)
	if errors.Is(err, os.ErrNotExist) {
		state.ImportedEventFile = ""
		return nil
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != state.ImportedEventsHash {
		return errors.New("activity spool file changed before acknowledgement")
	}
	if err = os.Remove(filename); err != nil {
		return err
	}
	state.ImportedEventFile = ""
	return nil
}
