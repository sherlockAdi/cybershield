package main

import "testing"

func TestCPUDeltaAndMissingCounters(t *testing.T) {
	before := parseCPU("cpu 100 0 50 850 0 0 0 0 20 0\n")
	after := parseCPU("cpu 130 0 70 900 0 0 0 0 90 0\n")
	value := cpuPercent(before, after)
	if value == nil || *value != 50 {
		t.Fatal("guest counters were counted twice or CPU delta was wrong")
	}
	if cpuPercent(after, before) != nil || cpuPercent(nil, after) != nil || cpuPercent(after, after) != nil {
		t.Fatal("invalid or unavailable CPU became zero")
	}
}
func TestMemoryUsesAvailableRatherThanFree(t *testing.T) {
	total, used := parseMemory("MemTotal: 1000 kB\nMemAvailable: 250 kB\nMemFree: 10 kB\n")
	if total == nil || used == nil || *total != 1024000 || *used != 768000 {
		t.Fatal("memory calculation wrong")
	}
	if total, _ := parseMemory("MemTotal: 1000 kB\nMemFree: 10 kB\n"); total != nil {
		t.Fatal("missing MemAvailable reported as valid")
	}
	if total, _ := parseMemory("MemTotal: 10 kB\nMemAvailable: 20 kB\n"); total != nil {
		t.Fatal("invalid memory ranges accepted")
	}
}
func TestStartupOutboxIsBoundedAndKeepsStableIDs(t *testing.T) {
	state := &agentState{}
	for index := 0; index < 100; index++ {
		if err := queueStartup(state); err != nil {
			t.Fatal(err)
		}
	}
	first := state.PendingEvents[0].SourceEventID
	if err := queueStartup(state); err == nil {
		t.Fatal("unbounded outbox")
	}
	if state.PendingEvents[0].SourceEventID != first {
		t.Fatal("retry changed event identity")
	}
}
