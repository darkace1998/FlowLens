package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// --- HTTP Basic Authentication middleware ---

// basicAuth wraps a handler with HTTP Basic Authentication when
// username and password are configured. If either is empty, an
// error is returned to prevent bypassing authentication due to misconfiguration.
// Credentials are SHA-256 hashed before comparison so that
// subtle.ConstantTimeCompare operates on fixed-length (32-byte)
// digests, preventing length-based timing side-channels.
func basicAuth(next http.Handler, username, password string) http.Handler {
	if username == "" && password == "" {
		// No authentication configured, allow all requests through
		return next
	}
	if username == "" || password == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Authentication not configured", http.StatusInternalServerError)
		})
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
// Tokens are stateless, consisting of a timestamp, a random nonce,
// and an HMAC-SHA256 signature to prevent tampering.
type csrfManager struct {
	secret []byte
	mu     sync.Mutex
	used   map[string]int64 // track used tokens to enforce single-use (token -> expiration)
}

func newCSRFManager() *csrfManager {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return &csrfManager{
		secret: secret,
		used:   make(map[string]int64),
	}
}

// generate creates a new random CSRF token.
// If crypto/rand fails, it panics to ensure the application
// does not continue executing in an insecure state.
func (m *csrfManager) generate() string {
	b := make([]byte, 32)

	// 8 bytes expiration timestamp (12 hours from now)
	exp := time.Now().Add(12 * time.Hour).Unix()
	binary.BigEndian.PutUint64(b[0:8], uint64(exp))

	// 8 bytes random nonce
	if _, err := rand.Read(b[8:16]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}

	// 16 bytes HMAC-SHA256 signature
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(b[0:16])
	sum := mac.Sum(nil)
	copy(b[16:32], sum[:16])

	return hex.EncodeToString(b)
}

// valid checks whether a token is valid, not expired, and not already used (single-use).
func (m *csrfManager) valid(token string) bool {
	if len(token) != 64 {
		return false
	}

	b, err := hex.DecodeString(token)
	if err != nil || len(b) != 32 {
		return false
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(b[0:16])
	sum := mac.Sum(nil)
	if subtle.ConstantTimeCompare(b[16:32], sum[:16]) != 1 {
		return false
	}

	// Verify expiration
	exp := int64(binary.BigEndian.Uint64(b[0:8]))
	now := time.Now().Unix()
	if now > exp {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Cleanup expired tokens lazily
	for k, v := range m.used {
		if now > v {
			delete(m.used, k)
		}
	}

	// Enforce single-use
	if _, exists := m.used[token]; exists {
		return false
	}

	m.used[token] = exp

	// Bounding the used map to prevent memory exhaustion by extreme valid-token flooding.
	if len(m.used) > 100000 {
		m.used = make(map[string]int64)
	}

	return true
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

// --- Security Headers middleware ---

// securityHeadersMiddleware adds a Content-Security-Policy header and other security headers to every response.
// Note: 'unsafe-inline' is required for existing inline scripts (dark mode toggle,
// Chart.js init) and inline styles in templates. A future improvement would be to
// refactor these to external files or use nonce-based CSP.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// --- Health-check bypass middleware ---

// exemptHealthz routes /healthz and /ping requests directly to the mux, bypassing
// the wrapped handler chain (which includes Basic Auth). This ensures
// Docker HEALTHCHECK and Kubernetes probes remain functional when
// authentication is enabled.
func exemptHealthz(authed http.Handler, mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/ping" {
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
