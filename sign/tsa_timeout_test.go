package sign

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGetTSAAppliesTimeout checks that a timestamp authority that accepts the
// connection but never responds cannot block signing forever.
func TestGetTSAAppliesTimeout(t *testing.T) {
	block := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// Close the handler before the server so Close does not wait on it.
	defer server.Close()
	defer close(block)

	ctx := &SignContext{SignData: SignData{
		DigestAlgorithm: crypto.SHA256,
		TSA:             TSA{URL: server.URL, Timeout: 200 * time.Millisecond},
	}}

	start := time.Now()
	if _, err := ctx.GetTSA([]byte("content")); err == nil {
		t.Fatal("expected the timestamp request to fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timestamp request was not bounded: %s", elapsed)
	}
}

// TestGetTSAZeroTimeoutKeepsLegacyBehavior checks the field is opt-in.
func TestGetTSAZeroTimeoutKeepsLegacyBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx := &SignContext{SignData: SignData{
		DigestAlgorithm: crypto.SHA256,
		TSA:             TSA{URL: server.URL},
	}}
	if got := ctx.SignData.TSA.Timeout; got != 0 {
		t.Fatalf("zero timeout should stay zero, got %s", got)
	}
	if _, err := ctx.GetTSA([]byte("content")); err == nil {
		t.Fatal("expected a non-2xx response to fail")
	}
}
