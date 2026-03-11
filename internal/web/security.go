package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// --- HTTP Basic Authentication middleware ---

// basicAuth wraps a handler with HTTP Basic Authentication when
// username and password are configured. If either is empty,
// authentication is disabled and the handler is returned as-is.
// Credentials are SHA-256 hashed before comparison so that
// subtle.ConstantTimeCompare operates on fixed-length (32-byte)
// digests, preventing length-based timing side-channels.
func basicAuth(next http.Handler, username, password string) http.Handler {
	if username == "" || password == "" {
		return next
	}
	wantUser := sha256.Sum256([]byte(username))
	wantPass := sha256.Sum256([]byte(password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		gotUser := sha256.Sum256([]byte(u))
		gotPass := sha256.Sum256([]byte(p))
		if !ok ||
			subtle.ConstantTimeCompare(gotUser[:], wantUser[:]) != 1 ||
			subtle.ConstantTimeCompare(gotPass[:], wantPass[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="FlowLens"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- CSRF token middleware ---

// csrfManager generates and validates per-session CSRF tokens.
type csrfManager struct {
	mu     sync.RWMutex
	tokens map[string]bool // active token set
}

func newCSRFManager() *csrfManager {
	return &csrfManager{tokens: make(map[string]bool)}
}

// generate creates a new random CSRF token and stores it.
// If crypto/rand fails, it returns an empty string — callers
// treat empty tokens as invalid, so CSRF protection fails closed.
func (m *csrfManager) generate() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	token := hex.EncodeToString(b)
	m.mu.Lock()
	m.tokens[token] = true
	// Keep at most 1000 tokens to bound memory.
	if len(m.tokens) > 1000 {
		for k := range m.tokens {
			delete(m.tokens, k)
			break
		}
	}
	m.mu.Unlock()
	return token
}

// valid checks whether a token is present and removes it (single-use).
func (m *csrfManager) valid(token string) bool {
	if token == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokens[token] {
		delete(m.tokens, token)
		return true
	}
	return false
}

// csrfProtect wraps a POST handler with CSRF token validation.
// The token is read from the "csrf_token" form field.
func (m *csrfManager) csrfProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			token := r.FormValue("csrf_token")
			if !m.valid(token) {
				http.Error(w, "Forbidden — invalid or missing CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// --- Content-Security-Policy middleware ---

// cspMiddleware adds a Content-Security-Policy header to every response.
// Note: 'unsafe-inline' is required for existing inline scripts (dark mode toggle,
// Chart.js init) and inline styles in templates. A future improvement would be to
// refactor these to external files or use nonce-based CSP.
func cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// --- Health-check bypass middleware ---

// exemptHealthz routes /healthz requests directly to the mux, bypassing
// the wrapped handler chain (which includes Basic Auth). This ensures
// Docker HEALTHCHECK and Kubernetes probes remain functional when
// authentication is enabled.
func exemptHealthz(authed http.Handler, mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			mux.ServeHTTP(w, r)
			return
		}
		authed.ServeHTTP(w, r)
	})
}

// --- Request timeout middleware ---

// requestTimeout adds a context deadline to each request. If the handler
// does not complete within the timeout, the client receives a 503 Service
// Unavailable response. This prevents hung requests from slow storage queries.
func requestTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.TimeoutHandler(next, timeout, "Request timed out")
}
