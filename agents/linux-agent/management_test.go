package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestManagementExpiredAndReplayedCommandsNeverExecute(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux agent persistence; Windows uses the .NET agent")
	}
	directory := t.TempDir()
	config := options{stateDir: directory, managementHelper: "/does/not/exist"}
	state := &agentState{}
	command := &hostCommand{ID: "12345678-1234-4234-9234-123456789abc", ExpiresAt: time.Now().Add(-time.Minute)}
	if err := executeManagement(context.Background(), config, state, command); err != nil {
		t.Fatal(err)
	}
	if state.ManagementResult.Success || state.ManagementResult.Message != "Command expired before execution" {
		t.Fatal(state.ManagementResult)
	}
	// Persisted result is reused even if a later delivery has a fresh expiration.
	command.ExpiresAt = time.Now().Add(time.Minute)
	if err := executeManagement(context.Background(), config, state, command); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved agentState
	if err = json.Unmarshal(content, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.ManagementResult.Message != "Command expired before execution" {
		t.Fatal("replayed helper invocation")
	}
}

func TestManagementBoundedOutput(t *testing.T) {
	output := &boundedBuffer{limit: 4}
	if _, err := output.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("5")); err == nil {
		t.Fatal("unbounded output")
	}
}
