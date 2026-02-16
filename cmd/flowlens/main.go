package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/darkace1998/FlowLens/internal/analysis"
	"github.com/darkace1998/FlowLens/internal/collector"
	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/geo"
	"github.com/darkace1998/FlowLens/internal/logging"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
	"github.com/darkace1998/FlowLens/internal/web"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	log := logging.Default()

	// Determine config file path.
	cfgPath := "configs/flowlens.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	// Load configuration.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Error("Failed to load config: %v", err)
		os.Exit(1)
	}

	log.Info("FlowLens %s starting", Version)

	// Initialise storage backends.
	ringBuf := storage.NewRingBuffer(10000)

	sqlStore, err := storage.NewSQLiteStore(cfg.Storage.SQLitePath, cfg.Storage.SQLiteRetention, cfg.Storage.PruneInterval)
	if err != nil {
		log.Error("Failed to open SQLite store: %v", err)
		os.Exit(1)
	}
	defer sqlStore.Close()

	// Flow handler: fan-out to both storage backends.
	// Use a WaitGroup to track in-flight handler calls for clean shutdown.
	var handlerWg sync.WaitGroup
	handler := func(flows []model.Flow) {
		handlerWg.Add(1)
		defer handlerWg.Done()
		if err := ringBuf.Insert(flows); err != nil {
			log.Warn("Ring buffer insert error: %v", err)
		}
		if err := sqlStore.Insert(flows); err != nil {
			log.Warn("SQLite insert error: %v", err)
		}
	}

	// Start collector.
	coll := collector.New(cfg.Collector, handler)
	go func() {
		if err := coll.Start(); err != nil {
			log.Error("Collector error: %v", err)
		}
	}()

	// Register all analysis modules.
	engine := analysis.NewEngine(cfg.Analysis, ringBuf,
		analysis.AnomalyDetector{},
		analysis.ScanDetector{},
		analysis.TopTalkers{},
		analysis.DNSVolume{},
		analysis.ProtocolDistribution{},
		analysis.RetransmissionDetector{},
		analysis.FlowAsymmetry{},
		analysis.PortConcentrationDetector{},
		analysis.UnreachableDetector{},
		analysis.NewTalkerDetector{},
		analysis.VoIPQualityDetector{},
	)
	go engine.Start()

	// Initialise GeoIP lookup.
	geoLookup := geo.New()
	if cfg.Storage.GeoIPPath != "" {
		if err := geoLookup.LoadCSV(cfg.Storage.GeoIPPath); err != nil {
			log.Warn("Failed to load GeoIP database: %v (using built-in ranges only)", err)
		} else {
			log.Info("Loaded GeoIP database from %s", cfg.Storage.GeoIPPath)
		}
	}

	// Start web server.
	// Resolve static directory relative to binary location if "static" doesn't exist in CWD.
	staticDir := "static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		if exe, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(exe), "static")
			if _, err := os.Stat(candidate); err == nil {
				staticDir = candidate
			}
		}
	}
	srv := web.NewServer(cfg.Web, ringBuf, sqlStore, staticDir, engine, geoLookup)
	srv.SetAboutInfo(cfg, Version, time.Now())
	go func() {
		if err := srv.Start(); err != nil {
			log.Error("Web server error: %v", err)
		}
	}()

	fmt.Printf("FlowLens %s is running. Press Ctrl+C to stop.\n", Version)

	// Wait for shutdown signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Info("Shutting down…")
	coll.Stop()
	handlerWg.Wait() // Wait for in-flight flow handlers to complete before closing storage.
	engine.Stop()
	if err := srv.Stop(); err != nil {
		log.Warn("Web server shutdown error: %v", err)
	}

	log.Info("FlowLens stopped.")
}
