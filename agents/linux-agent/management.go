package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"time"
)

type hostCommand struct {
	ID        string          `json:"id"`
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt time.Time       `json:"expiresAt"`
}
type commandResult struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Limit subprocess output without buffering an unbounded inventory.
type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("helper output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func callHelper(ctx context.Context, helper string, value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	deadline, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	process := exec.CommandContext(deadline, "/usr/bin/python3", helper)
	process.Stdin = bytes.NewReader(body)
	output := &boundedBuffer{limit: 220000}
	process.Stdout = output
	if err = process.Run(); err != nil {
		return nil, errors.New("management helper failed; inspect host service")
	}
	return output.Bytes(), nil
}
func managementReport(ctx context.Context, config options, state *agentState) map[string]any {
	report := map[string]any{"applications": []any{}, "rules": []any{}, "firewall": false, "errors": []string{}, "truncated": false}
	body, err := callHelper(ctx, config.managementHelper, map[string]string{"operation": "INVENTORY"})
	if err == nil {
		err = json.Unmarshal(body, &report)
	}
	if err != nil {
		report = map[string]any{"applications": []any{}, "rules": []any{}, "firewall": false, "errors": []string{"Management helper unavailable; check installation and permissions"}, "truncated": false}
	}
	report["results"] = []commandResult{}
	if state.ManagementResult != nil {
		report["results"] = []commandResult{*state.ManagementResult}
	}
	return report
}
func executeManagement(ctx context.Context, config options, state *agentState, command *hostCommand) error {
	if command == nil || config.managementHelper == "" {
		return nil
	}
	if state.ManagementResult != nil && state.ManagementResult.ID == command.ID {
		return nil
	}
	// Persist an indeterminate failure BEFORE executing: a crash must never replay a stop.
	state.ManagementResult = &commandResult{ID: command.ID, Message: "Execution interrupted; inspect host before retrying"}
	if err := saveState(config.stateDir, state); err != nil {
		return err
	}
	if time.Now().After(command.ExpiresAt) {
		state.ManagementResult.Message = "Command expired before execution"
		return saveState(config.stateDir, state)
	}
	body, err := callHelper(ctx, config.managementHelper, command)
	var result commandResult
	if err != nil || json.Unmarshal(body, &result) != nil || result.ID != command.ID {
		state.ManagementResult.Message = "Helper failed; inspect host before retrying"
	} else {
		state.ManagementResult = &result
	}
	return saveState(config.stateDir, state)
}
