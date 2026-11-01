package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlPlaneResponseFaultsFailClosed(t *testing.T) {
	key, _, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"accepted":true} {}`, `{"accepted":true}` + strings.Repeat(" ", 16384), `{"accepted":`, strings.Repeat("x", 16385)} {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { response.Write([]byte(body)) }))
		_, err := send(context.Background(), server.Client(), server.URL, "/api/agent/v1/heartbeat", key, map[string]int{"sequence": 1})
		server.Close()
		if err == nil {
			t.Fatal("malformed or oversized response accepted")
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Write([]byte(`{"accepted":true,"acceptedSequence":9}`))
	}))
	defer server.Close()
	result, err := send(context.Background(), server.Client(), server.URL, "/api/agent/v1/heartbeat", key, map[string]int{"sequence": 9})
	if err != nil || !result.Accepted || result.AcceptedSequence != 9 {
		t.Fatal("valid response rejected")
	}
}

func TestOutboxRestartAndCapacityDeferralPreserveReceipts(t *testing.T) {
	content := []byte(`{"sourceEventId":"auth:recovery","kind":"AUTH_FAILURE","severity":"INFO","occurredAt":"2026-10-30T12:00:00Z","payload":{"source":"fixture","service":"SSH","sourceIp":"192.0.2.1"}}`)
	state := &agentState{PendingEvents: make([]agentEvent, 100), ImportedEventsHash: "previous"}
	if err := importEventBytes(state, content); err != nil || len(state.PendingEvents) != 100 || state.ImportedEventsHash != "previous" {
		t.Fatal("capacity deferral lost pending state")
	}
	state.PendingEvents = nil
	if err := importEventBytes(state, content); err != nil {
		t.Fatal(err)
	}
	saved, _ := json.Marshal(state)
	var restored agentState
	if err := json.Unmarshal(saved, &restored); err != nil {
		t.Fatal(err)
	}
	if err := importEventBytes(&restored, content); err != nil || len(restored.PendingEvents) != 1 || restored.PendingEvents[0].SourceEventID != "auth:recovery" {
		t.Fatal("restart duplicated or lost queued event")
	}
	before := restored.ImportedEventsHash
	if err := importEventBytes(&restored, []byte("not JSON")); err == nil || restored.ImportedEventsHash != before || len(restored.PendingEvents) != 1 {
		t.Fatal("invalid replacement corrupted recoverable outbox")
	}
}

func FuzzEventFileImportIsAtomic(f *testing.F) {
	f.Add([]byte("invalid"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, content []byte) {
		state := &agentState{ImportedEventsHash: "original"}
		err := importEventBytes(state, content)
		if err != nil && (state.ImportedEventsHash != "original" || len(state.PendingEvents) != 0) {
			t.Fatal("failed import mutated durable state")
		}
		if len(state.PendingEvents) > 90 {
			t.Fatal("unbounded imported outbox")
		}
	})
}
