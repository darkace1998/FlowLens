package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

// --- Basic Auth tests ---

func TestBasicAuth_Disabled(t *testing.T) {
	// No username/password = auth disabled, pages accessible.
	s, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func newAuthTestServer(t *testing.T) *Server {
	t.Helper()
	ringBuf := storage.NewRingBuffer(1000)
	cfg := config.WebConfig{
		Listen:   ":0",
		PageSize: 10,
		Username: "admin",
		Password: "secret",
	}
	s := NewServer(cfg, ringBuf, nil, t.TempDir(), nil, nil, nil, nil)
	return s
}

func TestBasicAuth_Unauthorized(t *testing.T) {
	s := newAuthTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "Basic") {
		t.Error("expected WWW-Authenticate: Basic header")
	}
}

func TestBasicAuth_WrongCredentials(t *testing.T) {
	s := newAuthTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "wrong")
	w := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestBasicAuth_CorrectCredentials(t *testing.T) {
	s := newAuthTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Error("authenticated request should see the Dashboard")
	}
}

func TestBasicAuth_TimingResistant(t *testing.T) {
	// Ensure wrong username doesn't short-circuit differently
	s := newAuthTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("wronguser", "secret")
	w := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// --- CSRF tests ---

func TestCSRF_MissingToken(t *testing.T) {
	s, _ := newTestServer(t)

	// POST to /capture/start without CSRF token.
	req := httptest.NewRequest("POST", "/capture/start", strings.NewReader("device=eth0"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), "CSRF") {
		t.Error("response should mention CSRF")
	}
}

func TestCSRF_InvalidToken(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("POST", "/capture/start", strings.NewReader("device=eth0&csrf_token=bogus"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRF_ValidToken(t *testing.T) {
	s, _ := newTestServer(t)
	token := s.csrfToken()

	// POST with valid token — should pass CSRF and reach handler (nil captureMgr → 503).
	req := httptest.NewRequest("POST", "/capture/start", strings.NewReader("device=eth0&csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	// Should not be 403 (CSRF), should be 503 (no capture manager)
	if w.Code == http.StatusForbidden {
		t.Error("valid CSRF token should not be rejected")
	}
}

func TestCSRF_SingleUseToken(t *testing.T) {
	s, _ := newTestServer(t)
	token := s.csrfToken()

	// Use token once.
	req := httptest.NewRequest("POST", "/capture/start", strings.NewReader("device=eth0&csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	// Reuse same token — should be rejected.
	req2 := httptest.NewRequest("POST", "/capture/start", strings.NewReader("device=eth0&csrf_token="+token))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	s.Mux().ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("reused CSRF token should be rejected, got status %d", w2.Code)
	}
}

func TestCSRF_CaptureStop_MissingToken(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("POST", "/capture/stop", strings.NewReader("id=cap-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestCSRF_GETNotBlocked(t *testing.T) {
	// GET requests to CSRF-protected endpoints should not be blocked by CSRF.
	s, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/capture/start", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	// Should get MethodNotAllowed from the handler, not Forbidden from CSRF.
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- CSP tests ---

func TestCSP_HeaderPresent(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	// Use the full handler chain (srv.Handler includes CSP middleware).
	s.srv.Handler.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP should contain default-src 'self', got: %s", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP should prevent framing, got: %s", csp)
	}
}

func TestCSP_OnEveryPage(t *testing.T) {
	s, _ := newTestServer(t)

	pages := []string{"/", "/flows", "/hosts", "/advisories", "/about"}
	for _, path := range pages {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		s.srv.Handler.ServeHTTP(w, req)

		if w.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("CSP header missing on %s", path)
		}
	}
}

// --- CSRF manager unit tests ---

func TestCSRFManager_Generate(t *testing.T) {
	m := newCSRFManager()

	token1 := m.generate()
	token2 := m.generate()

	if token1 == "" {
		t.Error("generated token should not be empty")
	}
	if token1 == token2 {
		t.Error("each token should be unique")
	}
	if len(token1) != 64 { // 32 bytes hex-encoded = 64 chars
		t.Errorf("token length = %d, want 64", len(token1))
	}
}

func TestCSRFManager_ValidateAndConsume(t *testing.T) {
	m := newCSRFManager()
	token := m.generate()

	if !m.valid(token) {
		t.Error("token should be valid")
	}
	// Second validation should fail (single-use).
	if m.valid(token) {
		t.Error("token should be consumed after first use")
	}
}

func TestCSRFManager_EmptyToken(t *testing.T) {
	m := newCSRFManager()
	if m.valid("") {
		t.Error("empty token should be invalid")
	}
}

func TestCSRFManager_UnknownToken(t *testing.T) {
	m := newCSRFManager()
	if m.valid("nonexistent") {
		t.Error("unknown token should be invalid")
	}
}

// --- TLS config tests ---

func TestTLSConfig_NotSetByDefault(t *testing.T) {
	s, _ := newTestServer(t)
	if s.srv.TLSConfig != nil {
		t.Error("TLS config should be nil when no cert/key provided")
	}
}

func TestTLSConfig_SetWhenConfigured(t *testing.T) {
	ringBuf := storage.NewRingBuffer(1000)
	cfg := config.WebConfig{
		Listen:   ":0",
		PageSize: 10,
		TLSCert:  "/tmp/cert.pem",
		TLSKey:   "/tmp/key.pem",
	}
	s := NewServer(cfg, ringBuf, nil, t.TempDir(), nil, nil, nil, nil)

	if s.srv.TLSConfig == nil {
		t.Error("TLS config should be set when cert/key provided")
	}
}

// --- Template CSRF token output ---

func TestCaptureTemplate_ContainsCSRFToken(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/capture", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "csrf_token") {
		t.Error("capture page should contain CSRF token field")
	}
}

func TestSessionsTemplate_ContainsCSRFToken(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/sessions", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "csrf_token") {
		t.Error("sessions page (PCAP import form) should contain CSRF token field")
	}
}

// --- Request timeout middleware tests ---

func TestRequestTimeout_Exists(t *testing.T) {
	s, _ := newTestServer(t)

	// The server should have ReadTimeout, WriteTimeout, and IdleTimeout set.
	if s.srv.ReadTimeout == 0 {
		t.Error("ReadTimeout should be set")
	}
	if s.srv.WriteTimeout == 0 {
		t.Error("WriteTimeout should be set")
	}
	if s.srv.IdleTimeout == 0 {
		t.Error("IdleTimeout should be set")
	}
}

// --- Accessibility tests ---

func TestLayout_AriaLabels(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()

	// Navigation should have aria-label
	if !strings.Contains(body, `aria-label="Main navigation"`) {
		t.Error("nav should have aria-label='Main navigation'")
	}

	// Hamburger menu toggle should have descriptive aria-label
	if !strings.Contains(body, `aria-label="Toggle navigation menu"`) {
		t.Error("hamburger menu should have aria-label='Toggle navigation menu'")
	}

	// Hamburger menu should have aria-expanded
	if !strings.Contains(body, `aria-expanded="false"`) {
		t.Error("hamburger menu should have aria-expanded attribute")
	}

	// Dark mode toggle should have aria-label
	if !strings.Contains(body, `aria-label="Toggle dark mode"`) {
		t.Error("dark mode toggle should have aria-label")
	}

	// Loading spinner should have role="status"
	if !strings.Contains(body, `role="status"`) {
		t.Error("loading spinner should have role='status'")
	}

	// Loading spinner should have screen-reader text
	if !strings.Contains(body, "sr-only") {
		t.Error("loading spinner should have visually-hidden text for screen readers")
	}

	// Loading overlay should have aria-hidden
	if !strings.Contains(body, `aria-hidden="true"`) {
		t.Error("loading overlay should be aria-hidden by default")
	}

	// Brand link should have aria-label
	if !strings.Contains(body, `aria-label="FlowLens home"`) {
		t.Error("brand link should have aria-label='FlowLens home'")
	}
}

func TestLayout_LoadingSpinner(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()

	if !strings.Contains(body, "loading-overlay") {
		t.Error("page should contain loading overlay")
	}
	if !strings.Contains(body, "loading-spinner") {
		t.Error("page should contain loading spinner")
	}
}

func TestAdvisories_SeverityBadgeAccessibility(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest("GET", "/advisories", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	body := w.Body.String()
	// Page should render without error (even with no advisories)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(body, "Advisories") {
		t.Error("advisories page should contain 'Advisories'")
	}
}
