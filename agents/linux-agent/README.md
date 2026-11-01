# Linux agent

Go standard-library prototype with signed outbound enrollment, 30-second heartbeats, persistent P-256 identity, flushed sequences and Linux flock protection. No firewall/shell/job execution. Build with `go test ./...` and `CGO_ENABLED=0 go build -trimpath -o serverguard-agent .`. The systemd unit is an uninstalled least-privilege template. See [installation](../../docs/agent-guide.md), [protocol](../../docs/agent-protocol.md) and [verification](../../docs/week-3-checklist.md). The Linux amd64 binary is cross-compiled here; Linux runtime/systemd validation remains a VM gate.
