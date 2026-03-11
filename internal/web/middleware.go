package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/darkace1998/FlowLens/internal/logging"
)

// --- Structured request logging middleware ---

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// requestLogging logs every HTTP request with method, path, status code, and duration.
func requestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)
		logging.Default().Info("%s %s %d %s", r.Method, r.URL.Path, rec.statusCode, time.Since(start).Round(time.Millisecond))
	})
}

// --- Panic recovery middleware ---

// recoverMiddleware catches panics in downstream handlers and returns a
// 500 Internal Server Error instead of crashing the server process.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rv := recover(); rv != nil {
				logging.Default().Error("panic recovered: %v (request: %s %s)", rv, r.Method, r.URL.Path)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// --- Standardized error response helper ---

// httpError sends an HTTP error response and logs the error in a consistent
// format. Use this instead of separate http.Error + logging calls.
func httpError(w http.ResponseWriter, r *http.Request, msg string, code int, err error) { //nolint:unparam // code is kept as parameter for flexibility
	if err != nil {
		logging.Default().Error("%s %s: %s: %v", r.Method, r.URL.Path, msg, err)
	} else {
		logging.Default().Warn("%s %s: %s", r.Method, r.URL.Path, msg)
	}
	http.Error(w, msg, code)
}

// --- Health check endpoint ---

// handleHealthz returns a 200 OK with a JSON body indicating the service is alive.
// This is intended for container orchestration liveness probes (e.g. Kubernetes).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := map[string]string{
		"status": "ok",
		"uptime": time.Since(s.startTime).Round(time.Second).String(),
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logging.Default().Error("healthz JSON encode error: %v", err)
	}
}
