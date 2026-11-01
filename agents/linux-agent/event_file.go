package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

func importEventBytes(state *agentState, content []byte) error {
	if !utf8.Valid(content) {
		return errors.New("events file must be valid UTF-8")
	}
	if len(content) > 32768 {
		return errors.New("events file exceeds 32 KiB")
	}
	digest := sha256.Sum256(content)
	hash := hex.EncodeToString(digest[:])
	if hash == state.ImportedEventsHash {
		return nil
	}
	var incoming []agentEvent
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimPrefix(string(content), "\uFEFF"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event agentEvent
		decoder := json.NewDecoder(bytes.NewBufferString(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return errors.New("invalid normalized event JSONL")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("trailing event JSON content")
		}
		if event.Kind != "AUTH_FAILURE" && event.Kind != "AUTH_SUCCESS" && event.Kind != "PROCESS_START" && event.Kind != "NETWORK_CONNECTION" && event.Kind != "ICMP_ECHO" && event.Kind != "TELEMETRY_STATUS" {
			return errors.New("event-file supports authentication and process observations only")
		}
		if event.SourceEventID == "" || len(event.SourceEventID) > 128 || event.Payload["source"] == "" {
			return errors.New("missing event identity/source")
		}
		if seen[event.SourceEventID] {
			return errors.New("duplicate source identity in event file")
		}
		seen[event.SourceEventID] = true
		if _, err := time.Parse(time.RFC3339Nano, event.OccurredAt); err != nil {
			return errors.New("invalid event timestamp")
		}
		incoming = append(incoming, event)
		if len(incoming) > 90 {
			return errors.New("event file exceeds 90 observations")
		}
	}
	if len(state.PendingEvents)+len(incoming) > 100 {
		return nil
	}
	state.PendingEvents = append(state.PendingEvents, incoming...)
	state.ImportedEventsHash = hash
	return nil
}

func queueEventFile(state *agentState, filename string) error {
	if filename == "" {
		return nil
	}
	content, err := readPrivateFile(filename, 32768)
	if err != nil {
		return err
	}
	return importEventBytes(state, content)
}
