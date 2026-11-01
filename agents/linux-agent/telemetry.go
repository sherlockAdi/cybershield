package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type healthMetrics struct {
	SampledAt        string   `json:"sampledAt"`
	CPUPercent       *float64 `json:"cpuPercent"`
	MemoryTotalBytes *int64   `json:"memoryTotalBytes"`
	MemoryUsedBytes  *int64   `json:"memoryUsedBytes"`
	DiskTotalBytes   *int64   `json:"diskTotalBytes"`
	DiskUsedBytes    *int64   `json:"diskUsedBytes"`
}
type agentEvent struct {
	SourceEventID string            `json:"sourceEventId"`
	Kind          string            `json:"kind"`
	Severity      string            `json:"severity"`
	OccurredAt    string            `json:"occurredAt"`
	Payload       map[string]string `json:"payload"`
}
type cpuSample struct{ total, idle uint64 }
type healthCollector struct{ previous *cpuSample }

func parseCPU(content string) *cpuSample {
	lines := strings.SplitN(content, "\n", 2)
	fields := strings.Fields(lines[0])
	if len(fields) < 9 || fields[0] != "cpu" {
		return nil
	}
	var result cpuSample
	for index := 1; index <= 8; index++ {
		value, err := strconv.ParseUint(fields[index], 10, 64)
		if err != nil || ^uint64(0)-result.total < value {
			return nil
		}
		result.total += value
		if index == 4 || index == 5 {
			if ^uint64(0)-result.idle < value {
				return nil
			}
			result.idle += value
		}
	}
	return &result
}
func readCPU() *cpuSample {
	content, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	return parseCPU(string(content))
}
func cpuPercent(previous, current *cpuSample) *float64 {
	if previous == nil || current == nil || current.total <= previous.total || current.idle < previous.idle {
		return nil
	}
	total := current.total - previous.total
	idle := current.idle - previous.idle
	if idle > total {
		return nil
	}
	value := float64(total-idle) / float64(total) * 100
	return &value
}
func parseMemory(content string) (*int64, *int64) {
	values := map[string]int64{}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != "kB" || (fields[0] != "MemTotal:" && fields[0] != "MemAvailable:") {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || value < 0 || value > maxSequence/1024 {
			return nil, nil
		}
		values[fields[0]] = value * 1024
	}
	total, hasTotal := values["MemTotal:"]
	available, hasAvailable := values["MemAvailable:"]
	if !hasTotal || !hasAvailable || total <= 0 || available > total {
		return nil, nil
	}
	used := total - available
	return &total, &used
}
func newHealthCollector() *healthCollector { return &healthCollector{previous: readCPU()} }
func (collector *healthCollector) collect() healthMetrics {
	current := readCPU()
	metrics := healthMetrics{SampledAt: time.Now().UTC().Format(time.RFC3339Nano), CPUPercent: cpuPercent(collector.previous, current)}
	collector.previous = current
	if content, err := os.ReadFile("/proc/meminfo"); err == nil {
		metrics.MemoryTotalBytes, metrics.MemoryUsedBytes = parseMemory(string(content))
	}
	metrics.DiskTotalBytes, metrics.DiskUsedBytes = diskUsage()
	return metrics
}
func queueStartup(state *agentState) error {
	if len(state.PendingEvents) >= 100 {
		return fmt.Errorf("event outbox is full; restore ingestion before restarting")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	state.PendingEvents = append(state.PendingEvents, agentEvent{SourceEventID: base64.RawURLEncoding.EncodeToString(random), Kind: "AGENT_STARTED", Severity: "INFO", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Payload: map[string]string{"source": "serverguard-linux-agent", "message": "Agent process started"}})
	return nil
}
