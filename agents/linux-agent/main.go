package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const agentVersion = "0.9.0-management"
const maxSequence = int64(9007199254740991)

type options struct {
	managementHelper string
	apiURL           string
	serverID         string
	tokenFile        string
	eventsFile       string
	eventsDir        string
	stateDir         string
	caFile           string
	allowHTTP        bool
	once             bool
}

type agentState struct {
	ManagementResult   *commandResult `json:"managementResult,omitempty"`
	ServerID           string         `json:"serverId"`
	APIOrigin          string         `json:"apiOrigin"`
	PrivateKey         string         `json:"privateKey"`
	CredentialID       string         `json:"credentialId"`
	Sequence           int64          `json:"sequence"`
	ExpiresAt          string         `json:"expiresAt"`
	PendingEvents      []agentEvent   `json:"pendingEvents,omitempty"`
	ImportedEventsHash string         `json:"importedEventsHash,omitempty"`
	ImportedEventFile  string         `json:"importedEventFile,omitempty"`
}

type agentResponse struct {
	Command           *hostCommand `json:"command"`
	CredentialID      string       `json:"credentialId"`
	ServerID          string       `json:"serverId"`
	ExpiresAt         string       `json:"expiresAt"`
	Accepted          bool         `json:"accepted"`
	AcceptedSequence  int64        `json:"acceptedSequence"`
	HeartbeatInterval int          `json:"heartbeatIntervalSeconds"`
	AcceptedCount     int          `json:"acceptedCount"`
	DuplicateCount    int          `json:"duplicateCount"`
}

type responseError struct{ status int }

func (failure responseError) Error() string {
	return fmt.Sprintf("control plane returned HTTP %d", failure.status)
}
func fatalError(err error) bool {
	var response responseError
	return errors.As(err, &response) && response.status >= 400 && response.status < 500 && response.status != 429
}

func validateOrigin(raw string, allowHTTP bool) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("api must be an HTTPS origin without credentials, path, query or fragment")
	}
	address := net.ParseIP(parsed.Hostname())
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http" && address != nil && address.IsLoopback()) {
		return "", errors.New("HTTPS is required; HTTP is permitted only for an explicit literal-loopback development connection")
	}
	return strings.TrimRight(raw, "/"), nil
}

func newKey() (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), nil
}

func readKey(encoded string) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid persisted key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("persisted key must be P-256")
	}
	return key, nil
}

func exportedPublicKey(key *ecdsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})), nil
}

func signingMessage(endpoint, timestamp, nonce string, body []byte) []byte {
	hash := sha256.Sum256(body)
	return []byte("SG1\nPOST\n" + endpoint + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(hash[:]))
}

func signRequest(request *http.Request, key *ecdsa.PrivateKey, body []byte) error {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	hash := sha256.Sum256(signingMessage(request.URL.EscapedPath(), timestamp, nonce, body))
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-SG-Timestamp", timestamp)
	request.Header.Set("X-SG-Nonce", nonce)
	request.Header.Set("X-SG-Signature", base64.StdEncoding.EncodeToString(signature))
	return nil
}

func saveState(directory string, state *agentState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(encoded) > 131072 {
		return errors.New("agent state exceeds 128 KiB")
	}
	file, err := os.CreateTemp(directory, ".state-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(encoded)
	}
	if err == nil {
		err = file.Sync()
	}
	closeError := file.Close()
	if err != nil {
		return err
	}
	if closeError != nil {
		return closeError
	}
	if err = os.Rename(name, filepath.Join(directory, "state.json")); err != nil {
		return err
	}
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func loadState(config options) (*agentState, *ecdsa.PrivateKey, error) {
	filename := filepath.Join(config.stateDir, "state.json")
	if info, err := os.Lstat(filename); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 131072 {
			return nil, nil, errors.New("state file must be a private regular file (0600)")
		}
		encoded, err := readPrivateFile(filename, 131072)
		if err != nil {
			return nil, nil, err
		}
		var state agentState
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(encoded, &fields); err != nil {
			return nil, nil, errors.New("invalid persisted state JSON")
		}
		for _, required := range []string{"serverId", "apiOrigin", "privateKey", "sequence"} {
			if value, exists := fields[required]; !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, nil, errors.New("persisted state is missing identity or replay fields")
			}
		}
		if err = json.Unmarshal(encoded, &state); err != nil {
			return nil, nil, err
		}
		if state.ServerID != config.serverID || state.APIOrigin != config.apiURL || state.Sequence < 0 || state.Sequence > maxSequence {
			return nil, nil, errors.New("state identity, origin or sequence mismatch")
		}
		if len(state.PendingEvents) > 100 {
			return nil, nil, errors.New("persisted event outbox exceeds limit")
		}
		key, err := readKey(state.PrivateKey)
		return &state, key, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	key, encoded, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	state := &agentState{ServerID: config.serverID, APIOrigin: config.apiURL, PrivateKey: encoded}
	if err = saveState(config.stateDir, state); err != nil {
		return nil, nil, err
	}
	return state, key, nil
}

func httpClient(config options) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.caFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		encoded, err := os.ReadFile(config.caFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(encoded) {
			return nil, errors.New("CA file has no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func send(ctx context.Context, client *http.Client, origin, endpoint string, key *ecdsa.PrivateKey, value any) (*agentResponse, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if err = signRequest(request, key, body); err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("control-plane connection failed; check network, TLS and configured origin")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, responseError{response.StatusCode}
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(encoded) > 16384 {
		return nil, errors.New("control-plane response exceeds limit or cannot be read")
	}
	var result agentResponse
	if err = json.Unmarshal(encoded, &result); err != nil {
		return nil, errors.New("invalid control-plane response")
	}
	return &result, nil
}

func osVersion() string {
	content, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return truncate(strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\""), 100)
			}
		}
	}
	return "Linux"
}
func truncate(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
func uptime() int64 {
	content, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) || value > float64(maxSequence) {
		return 0
	}
	return int64(value)
}

func run(ctx context.Context, config options) error {
	if config.managementHelper != "" {
		if err := validateHelper(config.managementHelper); err != nil {
			return err
		}
	}
	if config.eventsFile != "" && config.eventsDir != "" {
		return errors.New("choose events-file or events-dir, not both")
	}
	if runtime.GOOS != "linux" {
		return errors.New("this agent runs on Linux; use --self-test for cross-platform protocol verification")
	}
	origin, err := validateOrigin(config.apiURL, config.allowHTTP)
	if err != nil {
		return err
	}
	config.apiURL = origin
	if config.serverID == "" {
		return errors.New("server-id is required")
	}
	if err = os.MkdirAll(config.stateDir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(config.stateDir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return errors.New("state-dir must be a private directory (0700)")
	}
	unlock, err := lockState(config.stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	state, key, err := loadState(config)
	if err != nil {
		return err
	}
	if err = queueStartup(state); err != nil {
		return err
	}
	if err = saveState(config.stateDir, state); err != nil {
		return err
	}
	collector := newHealthCollector()
	client, err := httpClient(config)
	if err != nil {
		return err
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	metadata := map[string]any{"schemaVersion": 1, "serverId": state.ServerID, "hostname": host, "os": "LINUX", "osVersion": osVersion(), "agentVersion": agentVersion}
	backoff := 5 * time.Second
	for {
		if err = queueEventFile(state, config.eventsFile); err != nil {
			return err
		}
		if err = queueActivitySpool(state, config.eventsDir); err != nil {
			return err
		}
		if err = saveState(config.stateDir, state); err != nil {
			return err
		}
		interval := 30 * time.Second
		if state.CredentialID == "" {
			var enrollmentToken []byte
			tokenInfo, statError := os.Lstat(config.tokenFile)
			if statError != nil || !tokenInfo.Mode().IsRegular() || tokenInfo.Mode().Perm()&0077 != 0 {
				return errors.New("first enrollment requires a private regular token-file (0600)")
			}
			enrollmentToken, err = readPrivateFile(config.tokenFile, 1024)
			if err != nil {
				return err
			}
			if len(enrollmentToken) > 1024 {
				return errors.New("token file is too large")
			}
			public, exportError := exportedPublicKey(key)
			if exportError != nil {
				return exportError
			}
			metadata["token"] = strings.TrimSpace(string(enrollmentToken))
			metadata["publicKey"] = public
			var response *agentResponse
			response, err = send(ctx, client, origin, "/api/agent/v1/enroll", key, metadata)
			delete(metadata, "token")
			delete(metadata, "publicKey")
			if err == nil {
				if response.ServerID != state.ServerID || response.CredentialID == "" {
					return errors.New("enrollment response identity mismatch")
				}
				state.CredentialID, state.ExpiresAt = response.CredentialID, response.ExpiresAt
				if err = saveState(config.stateDir, state); err != nil {
					return err
				}
				log.Print("enrollment accepted; local identity saved")
			}
		}
		if err == nil {
			if state.Sequence >= maxSequence {
				return errors.New("sequence exhausted; request a new enrollment")
			}
			state.Sequence++
			if err = saveState(config.stateDir, state); err != nil {
				return err
			}
			metadata["credentialId"], metadata["sequence"], metadata["uptimeSeconds"] = state.CredentialID, state.Sequence, uptime()
			metadata["inventory"] = map[string]any{"architecture": runtime.GOARCH, "logicalCpuCount": runtime.NumCPU()}
			metadata["metrics"] = collector.collect()
			if config.managementHelper != "" {
				metadata["management"] = managementReport(ctx, config, state)
			}
			var response *agentResponse
			response, err = send(ctx, client, origin, "/api/agent/v1/heartbeat", key, metadata)
			if err == nil {
				if !response.Accepted || response.ServerID != state.ServerID || response.AcceptedSequence != state.Sequence {
					return errors.New("heartbeat response mismatch")
				}
				if response.HeartbeatInterval >= 10 && response.HeartbeatInterval <= 300 {
					interval = time.Duration(response.HeartbeatInterval) * time.Second
				}
				if err = executeManagement(ctx, config, state, response.Command); err != nil {
					return err
				}
				log.Printf("heartbeat accepted (sequence %d)", state.Sequence)
			}
		}
		if err == nil && len(state.PendingEvents) > 0 {
			if state.Sequence >= maxSequence {
				return errors.New("sequence exhausted; request a new enrollment")
			}
			state.Sequence++
			if err = saveState(config.stateDir, state); err != nil {
				return err
			}
			var response *agentResponse
			response, err = send(ctx, client, origin, "/api/agent/v1/events", key, map[string]any{"schemaVersion": 1, "serverId": state.ServerID, "credentialId": state.CredentialID, "sequence": state.Sequence, "events": state.PendingEvents})
			if err == nil {
				if !response.Accepted || response.ServerID != state.ServerID || response.AcceptedSequence != state.Sequence || response.AcceptedCount < 0 || response.DuplicateCount < 0 || response.AcceptedCount > len(state.PendingEvents) || response.DuplicateCount > len(state.PendingEvents) || response.AcceptedCount+response.DuplicateCount != len(state.PendingEvents) {
					return errors.New("event acknowledgement mismatch")
				}
				if err = acknowledgeActivitySpool(state, config.eventsDir); err != nil {
					return err
				}
				state.PendingEvents = nil
				if err = saveState(config.stateDir, state); err != nil {
					return err
				}
				log.Print("event outbox acknowledged")
			}
		}
		if err != nil {
			if config.once || fatalError(err) {
				return err
			}
			log.Print(err)
			jitter, randomError := rand.Int(rand.Reader, big.NewInt(int64(time.Second)))
			if randomError != nil {
				return randomError
			}
			interval = backoff + time.Duration(jitter.Int64())
			backoff = min(backoff*2, 5*time.Minute)
		} else {
			if config.once {
				return nil
			}
			backoff = 5 * time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		err = nil
	}
}

func selfTest() error {
	key, _, err := newKey()
	if err != nil {
		return err
	}
	public, err := exportedPublicKey(key)
	if err != nil {
		return err
	}
	message := signingMessage("/api/agent/v1/heartbeat", "1700000000", "abcdefghijklmnopqrstuv", []byte(`{"schemaVersion":1}`))
	hash := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, hash[:], signature) {
		return errors.New("signature self-test failed")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"publicKey": public, "message": string(message), "signature": base64.StdEncoding.EncodeToString(signature)})
}

func main() {
	var config options
	flag.StringVar(&config.managementHelper, "management-helper", "", "optional root-owned management helper Python script")
	flag.StringVar(&config.apiURL, "api", "", "control-plane HTTPS origin")
	flag.StringVar(&config.serverID, "server-id", "", "registered server UUID")
	flag.StringVar(&config.tokenFile, "token-file", "", "private enrollment token file; required only before first enrollment")
	flag.StringVar(&config.eventsFile, "events-file", "", "optional private normalized auth/process JSONL input file")
	flag.StringVar(&config.eventsDir, "events-dir", "", "optional private immutable activity JSONL spool; removed only after acknowledgement")
	flag.StringVar(&config.stateDir, "state-dir", "/var/lib/serverguard-agent", "private persistent agent state directory")
	flag.StringVar(&config.caFile, "ca-file", "", "optional trusted PEM CA bundle")
	flag.BoolVar(&config.allowHTTP, "allow-loopback-http", false, "explicit local-development HTTP exception")
	flag.BoolVar(&config.once, "once", false, "enroll if needed, send one heartbeat, then exit")
	self := flag.Bool("self-test", false, "verify and emit a non-secret protocol interoperability vector")
	flag.Parse()
	if *self {
		if err := selfTest(); err != nil {
			log.Fatal(err)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, config); err != nil {
		log.Fatal(err)
	}
}
