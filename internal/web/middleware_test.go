package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHealthz verifies the /healthz endpoint returns a 200 OK with JSON body.
func TestHealthz(t *testing.T) {
	s, _ := newTestServer(t)
	s.startTime = time.Now().Add(-5 * time.Minute) // simulate 5min uptime

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want ok", resp["status"])
	}
	if resp["uptime"] == "" {
		t.Error("uptime should not be empty")
	}
}

// TestRecoverMiddleware verifies that a panicking handler doesn't crash the server.
func TestRecoverMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := recoverMiddleware(inner)
	req := httptest.NewRequest("GET", "/panic", nil)
	w := httptest.NewRecorder()

	// Should not panic.
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(w.Body.String(), "Internal Server Error") {
		t.Errorf("body = %q, want 'Internal Server Error'", w.Body.String())
	}
}

// TestRequestLogging verifies the logging middleware wraps requests without errors.
func TestRequestLogging(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := requestLogging(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestStatusRecorder verifies that the statusRecorder captures the written status code.
func TestStatusRecorder(t *testing.T) {
	w := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

	rec.WriteHeader(http.StatusNotFound)

	if rec.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want %d", rec.statusCode, http.StatusNotFound)
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("underlying ResponseWriter code = %d, want %d", w.Code, http.StatusNotFound)
	}
}
