package analysis

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendWebhook_EmptyURL(t *testing.T) {
	// Should be a no-op — no panic.
	sendWebhook("", []Advisory{{Severity: WARNING, Title: "test"}})
}

func TestSendWebhook_EmptyAdvisories(t *testing.T) {
	// Should be a no-op even with a URL.
	sendWebhook("http://example.com/hook", nil)
}

func TestSendWebhook_SendsPayload(t *testing.T) {
	var received webhookPayload
	var gotRequest bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequest = true
		if r.Method != "POST" {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("JSON decode error: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	advisories := []Advisory{
		{
			Severity:    CRITICAL,
			Timestamp:   time.Now(),
			Title:       "Test Advisory",
			Description: "Something bad happened",
			Action:      "Fix it",
		},
		{
			Severity:    WARNING,
			Timestamp:   time.Now(),
			Title:       "Minor Issue",
			Description: "Something is off",
			Action:      "Investigate",
		},
	}

	sendWebhook(server.URL, advisories)

	if !gotRequest {
		t.Fatal("webhook server did not receive request")
	}
	if len(received.Advisories) != 2 {
		t.Errorf("received %d advisories, want 2", len(received.Advisories))
	}
	if received.Advisories[0].Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", received.Advisories[0].Severity)
	}
	if received.Advisories[0].Title != "Test Advisory" {
		t.Errorf("title = %q, want 'Test Advisory'", received.Advisories[0].Title)
	}
}

func TestSendWebhook_HandlesErrorGracefully(t *testing.T) {
	// Should not panic on connection failure.
	sendWebhook("http://127.0.0.1:1", []Advisory{{Severity: INFO, Title: "test"}})
}
