package web

import (
	"embed"
	"html/template"
	"net/http"
	"time"

	"github.com/darkace1998/FlowLens/internal/analysis"
	"github.com/darkace1998/FlowLens/internal/capture"
	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/geo"
	"github.com/darkace1998/FlowLens/internal/logging"
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
	geoLookup *geo.Lookup
	captureMgr *capture.Manager
	mux      *http.ServeMux
	srv      *http.Server

	// Pre-parsed templates
	tmplDashboard  *template.Template
	tmplFlows      *template.Template
	tmplAdvisories *template.Template
	tmplAbout      *template.Template
	tmplHosts      *template.Template
	tmplReports    *template.Template
	tmplMap        *template.Template
	tmplCapture    *template.Template
	tmplVLANs      *template.Template
	tmplMACs       *template.Template

	// About page info
	fullCfg   config.Config
	version   string
	startTime time.Time
}

// NewServer creates a new web server with the given config and storage backends.
func NewServer(cfg config.WebConfig, ringBuf *storage.RingBuffer, sqlStore *storage.SQLiteStore, staticDir string, engine *analysis.Engine, geoLookup *geo.Lookup, captureMgr *capture.Manager) *Server {
	s := &Server{
		cfg:        cfg,
		ringBuf:    ringBuf,
		sqlStore:   sqlStore,
		engine:     engine,
		geoLookup:  geoLookup,
		captureMgr: captureMgr,
		mux:        http.NewServeMux(),
	}

	// Parse templates once at startup.
	s.tmplDashboard = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/dashboard.xhtml"))
	s.tmplFlows = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/flows.xhtml"))
	s.tmplAdvisories = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/advisories.xhtml"))
	s.tmplAbout = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/about.xhtml"))
	s.tmplHosts = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/hosts.xhtml"))
	s.tmplReports = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/reports.xhtml"))
	s.tmplMap = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/map.xhtml"))
	s.tmplCapture = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/capture.xhtml"))
	s.tmplVLANs = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/vlans.xhtml"))
	s.tmplMACs = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, "templates/layout.xhtml", "templates/macs.xhtml"))

	s.mux.HandleFunc("/", s.handleDashboard)
	s.mux.HandleFunc("/flows", s.handleFlows)
	s.mux.HandleFunc("/hosts", s.handleHosts)
	s.mux.HandleFunc("/reports", s.handleReports)
	s.mux.HandleFunc("/reports/export", s.handleReportsExport)
	s.mux.HandleFunc("/advisories", s.handleAdvisories)
	s.mux.HandleFunc("/about", s.handleAbout)
	s.mux.HandleFunc("/map", s.handleMap)
	s.mux.HandleFunc("/capture", s.handleCapture)
	s.mux.HandleFunc("/capture/start", s.handleCaptureStart)
	s.mux.HandleFunc("/capture/stop", s.handleCaptureStop)
	s.mux.HandleFunc("/capture/download", s.handleCaptureDownload)
	s.mux.HandleFunc("/vlans", s.handleVLANs)
	s.mux.HandleFunc("/macs", s.handleMACs)
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
	logging.Default().Info("Web server listening on %s", s.cfg.Listen)
	return s.srv.ListenAndServe()
}

// Stop gracefully shuts down the web server.
func (s *Server) Stop() error {
	return s.srv.Close()
}

// SetAboutInfo configures the information displayed on the About page.
func (s *Server) SetAboutInfo(cfg config.Config, version string, startTime time.Time) {
	s.fullCfg = cfg
	s.version = version
	s.startTime = startTime
}

// Mux returns the underlying ServeMux for testing purposes.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}
