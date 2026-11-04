package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStateLockRejectsConcurrentProcess(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockState(directory)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockState(directory); err == nil {
		second()
		t.Fatal("concurrent state lock accepted")
	}
	unlock()
	last, err := lockState(directory)
	if err != nil {
		t.Fatal(err)
	}
	last()
}

func TestRunEnrollsAndResumesPersistedIdentity(t *testing.T) {
	var public *ecdsa.PublicKey
	var lastSequence int64
	enrollments := 0
	serverID := "22222222-2222-4222-8222-222222222222"
	credentialID := "11111111-1111-4111-8111-111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		var data map[string]json.RawMessage
		if err := json.Unmarshal(body, &data); err != nil {
			t.Error(err)
			response.WriteHeader(400)
			return
		}
		if request.URL.Path == "/api/agent/v1/enroll" {
			var encoded string
			json.Unmarshal(data["publicKey"], &encoded)
			block, _ := pem.Decode([]byte(encoded))
			if block == nil {
				t.Error("public key missing")
				response.WriteHeader(400)
				return
			}
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Error(err)
				response.WriteHeader(400)
				return
			}
			public = key.(*ecdsa.PublicKey)
			enrollments++
		}
		if public == nil {
			t.Error("missing bound identity")
			response.WriteHeader(401)
			return
		}
		hash := sha256.Sum256(signingMessage(request.URL.Path, request.Header.Get("X-SG-Timestamp"), request.Header.Get("X-SG-Nonce"), body))
		signature, _ := base64.StdEncoding.DecodeString(request.Header.Get("X-SG-Signature"))
		if !ecdsa.VerifyASN1(public, hash[:], signature) {
			t.Error("native request signature invalid")
			response.WriteHeader(401)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/api/agent/v1/enroll" {
			json.NewEncoder(response).Encode(agentResponse{CredentialID: credentialID, ServerID: serverID, ExpiresAt: "2030-01-01T00:00:00Z", HeartbeatInterval: 30})
			return
		}
		var sequence int64
		json.Unmarshal(data["sequence"], &sequence)
		if sequence <= lastSequence {
			t.Error("heartbeat sequence did not advance")
			response.WriteHeader(409)
			return
		}
		lastSequence = sequence
		acceptedCount := 0
		if request.URL.Path == "/api/agent/v1/events" {
			var events []agentEvent
			json.Unmarshal(data["events"], &events)
			acceptedCount = len(events)
		}
		json.NewEncoder(response).Encode(agentResponse{Accepted: true, ServerID: serverID, AcceptedSequence: sequence, HeartbeatInterval: 30, AcceptedCount: acceptedCount})
	}))
	defer server.Close()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "enrollment.token")
	if err := os.WriteFile(tokenFile, []byte("synthetic-enrollment-token-for-unit-testing"), 0600); err != nil {
		t.Fatal(err)
	}
	config := options{apiURL: server.URL, serverID: serverID, tokenFile: tokenFile, stateDir: directory, allowHTTP: true, once: true}
	if err := run(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if lastSequence != 2 {
		t.Fatal("first heartbeat and startup event not received")
	}
	config.tokenFile = ""
	if err := run(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if lastSequence != 4 || enrollments != 1 {
		t.Fatal("agent did not resume its original enrollment and sequence")
	}
	info, err := os.Stat(filepath.Join(directory, "state.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("state permissions are not private")
	}
}
