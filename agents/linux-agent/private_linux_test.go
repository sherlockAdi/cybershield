package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPrivateFilesRejectLinksPermissionsAndOversize(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "input")
	if err := os.WriteFile(filename, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(filename, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(filename, 6); err == nil {
		t.Fatal("oversized input accepted")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(link, 100); err == nil {
		t.Fatal("symbolic link accepted")
	}
	if err := os.Chmod(filename, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(filename, 100); err == nil {
		t.Fatal("publicly readable file accepted")
	}
	fifo := filepath.Join(directory, "pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFile(fifo, 100); err == nil {
		t.Fatal("pipe accepted")
	}
}

func TestCorruptStateNeverResetsIdentityOrSequence(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	config := options{stateDir: directory, serverID: "11111111-1111-4111-8111-111111111111", apiURL: "https://example.test"}
	state, key, err := loadState(config)
	if err != nil {
		t.Fatal(err)
	}
	state.Sequence = 42
	if err = saveState(directory, state); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "state.json")
	original, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range [][]byte{[]byte("{broken"), []byte(strings.Repeat("x", 131073))} {
		if err = os.WriteFile(filename, corrupt, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err = loadState(config); err == nil {
			t.Fatal("corrupt state accepted")
		}
		current, _ := os.ReadFile(filename)
		if string(current) != string(corrupt) {
			t.Fatal("corrupt state silently replaced")
		}
	}
	if err = os.WriteFile(filename, original, 0600); err != nil {
		t.Fatal(err)
	}
	restored, restoredKey, err := loadState(config)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Sequence != 42 || restoredKey.D.Cmp(key.D) != 0 {
		t.Fatal("recovery changed durable identity or sequence")
	}
	restored.PrivateKey = strings.Repeat("x", 131073)
	if err = saveState(directory, restored); err == nil {
		t.Fatal("oversized state saved")
	}
	current, _ := os.ReadFile(filename)
	if string(current) != string(original) {
		t.Fatal("failed save replaced last durable state")
	}
}
