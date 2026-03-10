package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
)

// --- HTTP Basic Authentication middleware ---

// basicAuth wraps a handler with HTTP Basic Authentication when
// username and password are configured. If either is empty,
// authentication is disabled and the handler is returned as-is.
func basicAuth(next http.Handler, username, password string) http.Handler {
	if username == "" || password == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
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
func (m *csrfManager) generate() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a less secure but still usable token on rand failure.
		return hex.EncodeToString(b)
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
