package main

import (
	"testing"
)

func TestEventFileImportIsDurableBoundedAndIdempotent(t *testing.T) {
	state := &agentState{}
	content := []byte(`{"sourceEventId":"ssh:1","kind":"AUTH_FAILURE","severity":"INFO","occurredAt":"2026-10-29T12:00:00Z","payload":{"source":"linux-journal-sshd","service":"SSH","sourceIp":"192.0.2.1"}}`)
	if err := importEventBytes(state, content); err != nil {
		t.Fatal(err)
	}
	if len(state.PendingEvents) != 1 || state.ImportedEventsHash == "" {
		t.Fatal("event and input receipt were not saved together")
	}
	if err := importEventBytes(state, content); err != nil || len(state.PendingEvents) != 1 {
		t.Fatal("identical input imported twice")
	}
	state.PendingEvents = nil
	if err := importEventBytes(state, content); err != nil || len(state.PendingEvents) != 0 {
		t.Fatal("acknowledged file replayed")
	}
	if err := importEventBytes(state, append(content, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if err := importEventBytes(state, make([]byte, 32769)); err == nil {
		t.Fatal("oversize input accepted")
	}
}
