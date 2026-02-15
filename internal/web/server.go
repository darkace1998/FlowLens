package web

import (
	"embed"
	"log"
	"net/http"

	"github.com/darkace1998/FlowLens/internal/analysis"
	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/storage"
)

//go:embed templates/*.xhtml
var templateFS embed.FS

// Server is the HTTP web server for FlowLens.
type Server struct {
	cfg      config.WebConfig
	ringBuf  *storage.RingBuffer
	sqlStore *storage.SQLiteStore
	engine   *analysis.Engine
	mux      *http.ServeMux
	srv      *http.Server
}

// NewServer creates a new web server with the given config and storage backends.
func NewServer(cfg config.WebConfig, ringBuf *storage.RingBuffer, sqlStore *storage.SQLiteStore, staticDir string, engine *analysis.Engine) *Server {
	s := &Server{
		cfg:      cfg,
		ringBuf:  ringBuf,
		sqlStore: sqlStore,
		engine:   engine,
		mux:      http.NewServeMux(),
	}

	s.mux.HandleFunc("/", s.handleDashboard)
	s.mux.HandleFunc("/flows", s.handleFlows)
	s.mux.HandleFunc("/advisories", s.handleAdvisories)
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	s.srv = &http.Server{
		Addr:    cfg.Listen,
		Handler: s.mux,
	}

	return s
}

// Start begins listening and serving HTTP requests. It blocks until the server
// is shut down or encounters a fatal error.
func (s *Server) Start() error {
	log.Printf("Web server listening on %s", s.cfg.Listen)
	return s.srv.ListenAndServe()
}

// Stop gracefully shuts down the web server.
func (s *Server) Stop() error {
	return s.srv.Close()
}

// Mux returns the underlying ServeMux for testing purposes.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}
