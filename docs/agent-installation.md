# Agent installation — Week 3 prototypes

The Go Linux agent and .NET Windows Worker/Windows Service prototypes implement outbound signed enrollment and heartbeats. Read the [build and installation guide](agent-guide.md), [wire protocol](agent-protocol.md) and [verification status](week-3-checklist.md). No host service was installed automatically.

These unsigned development packages report identity and health metadata only. Firewall execution, job polling, certificate issuance/mTLS, signed production packaging and automated certificate/key renewal remain later work. Remote connections require HTTPS; a literal-loopback-only HTTP flag exists for explicit same-machine tests. Validate Linux/systemd and Windows Server/SCM deployments in disposable VMs before production installation.
# Week 8 observation forwarding

Both updated prototypes support optional `--events-file` for a private, bounded normalized auth/process JSONL batch. This is not automatic OS-log collection. Follow [normalization, permissions, delivery verification and limits](detections.md) before enabling it; never put private keys or tokens in the file.

