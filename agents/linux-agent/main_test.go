package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportOriginSafety(t *testing.T) {
	for _, address := range []string{"http://example.com", "http://localhost:4100", "https://user:password@example.com", "https://example.com/api", "https://example.com?token=value", "ftp://127.0.0.1"} {
		if _, err := validateOrigin(address, true); err == nil {
			t.Fatalf("unsafe origin accepted: %s", address)
		}
	}
	if _, err := validateOrigin("http://127.0.0.1:4100", false); err == nil {
		t.Fatal("HTTP accepted without explicit development flag")
	}
	if _, err := validateOrigin("http://127.0.0.1:4100", true); err != nil {
		t.Fatal(err)
	}
	if _, err := validateOrigin("https://control.example.com", false); err != nil {
		t.Fatal(err)
	}
}

func TestSigningCoversExactBodyAndTarget(t *testing.T) {
	key, encoded, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := readKey(encoded)
	if err != nil || !restored.Equal(key) {
		t.Fatal("key did not round-trip")
	}
	body := []byte(`{"schemaVersion":1}`)
	request, _ := http.NewRequest(http.MethodPost, "https://example.com/api/agent/v1/heartbeat", nil)
	if err = signRequest(request, key, body); err != nil {
		t.Fatal(err)
	}
	signature, _ := base64.StdEncoding.DecodeString(request.Header.Get("X-SG-Signature"))
	hash := sha256.Sum256(signingMessage(request.URL.Path, request.Header.Get("X-SG-Timestamp"), request.Header.Get("X-SG-Nonce"), body))
	if !ecdsa.VerifyASN1(&key.PublicKey, hash[:], signature) {
		t.Fatal("signature failed")
	}
	changed := sha256.Sum256(signingMessage("/api/agent/v1/enroll", request.Header.Get("X-SG-Timestamp"), request.Header.Get("X-SG-Nonce"), body))
	if ecdsa.VerifyASN1(&key.PublicKey, changed[:], signature) {
		t.Fatal("signature accepted a different target")
	}
}

func TestRedirectDoesNotForwardEnrollmentToken(t *testing.T) {
	received := false
	destination := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		received = true
		io.WriteString(response, "unexpected")
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, err := httpClient(options{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if received || response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatal("redirect followed")
	}
}
