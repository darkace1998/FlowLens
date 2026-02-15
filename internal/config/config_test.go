package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.Collector.NetFlowPort != 2055 {
		t.Errorf("expected NetFlowPort 2055, got %d", cfg.Collector.NetFlowPort)
	}
	if cfg.Collector.IPFIXPort != 4739 {
		t.Errorf("expected IPFIXPort 4739, got %d", cfg.Collector.IPFIXPort)
	}
	if cfg.Collector.BufferSize != 65535 {
		t.Errorf("expected BufferSize 65535, got %d", cfg.Collector.BufferSize)
	}
	if cfg.Storage.RingBufferDuration != 10*time.Minute {
		t.Errorf("expected RingBufferDuration 10m, got %s", cfg.Storage.RingBufferDuration)
	}
	if cfg.Storage.SQLitePath != "./flowlens.db" {
		t.Errorf("expected SQLitePath ./flowlens.db, got %s", cfg.Storage.SQLitePath)
	}
	if cfg.Storage.SQLiteRetention != 72*time.Hour {
		t.Errorf("expected SQLiteRetention 72h, got %s", cfg.Storage.SQLiteRetention)
	}
	if cfg.Storage.PruneInterval != 15*time.Minute {
		t.Errorf("expected PruneInterval 15m, got %s", cfg.Storage.PruneInterval)
	}
	if cfg.Analysis.Interval != 60*time.Second {
		t.Errorf("expected Analysis.Interval 60s, got %s", cfg.Analysis.Interval)
	}
	if cfg.Analysis.TopTalkersCount != 10 {
		t.Errorf("expected TopTalkersCount 10, got %d", cfg.Analysis.TopTalkersCount)
	}
	if cfg.Analysis.ScanThreshold != 500 {
		t.Errorf("expected ScanThreshold 500, got %d", cfg.Analysis.ScanThreshold)
	}
	if cfg.Web.Listen != ":8080" {
		t.Errorf("expected Listen :8080, got %s", cfg.Web.Listen)
	}
	if cfg.Web.PageSize != 50 {
		t.Errorf("expected PageSize 50, got %d", cfg.Web.PageSize)
	}
}

func TestLoad(t *testing.T) {
	yamlContent := `
collector:
  netflow_port: 9995
  buffer_size: 32768
storage:
  sqlite_path: "/tmp/test.db"
  sqlite_retention: 24h
web:
  listen: ":9090"
  page_size: 25
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Overridden values
	if cfg.Collector.NetFlowPort != 9995 {
		t.Errorf("expected NetFlowPort 9995, got %d", cfg.Collector.NetFlowPort)
	}
	if cfg.Collector.BufferSize != 32768 {
		t.Errorf("expected BufferSize 32768, got %d", cfg.Collector.BufferSize)
	}
	if cfg.Storage.SQLitePath != "/tmp/test.db" {
		t.Errorf("expected SQLitePath /tmp/test.db, got %s", cfg.Storage.SQLitePath)
	}
	if cfg.Storage.SQLiteRetention != 24*time.Hour {
		t.Errorf("expected SQLiteRetention 24h, got %s", cfg.Storage.SQLiteRetention)
	}
	if cfg.Web.Listen != ":9090" {
		t.Errorf("expected Listen :9090, got %s", cfg.Web.Listen)
	}
	if cfg.Web.PageSize != 25 {
		t.Errorf("expected PageSize 25, got %d", cfg.Web.PageSize)
	}

	// Default values should be preserved for unset fields
	if cfg.Collector.IPFIXPort != 4739 {
		t.Errorf("expected default IPFIXPort 4739, got %d", cfg.Collector.IPFIXPort)
	}
	if cfg.Storage.RingBufferDuration != 10*time.Minute {
		t.Errorf("expected default RingBufferDuration 10m, got %s", cfg.Storage.RingBufferDuration)
	}
	if cfg.Analysis.Interval != 60*time.Second {
		t.Errorf("expected default Analysis.Interval 60s, got %s", cfg.Analysis.Interval)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	// Use content with a mapping value where a sequence is expected to trigger a parse error.
	if err := os.WriteFile(path, []byte("collector:\n  netflow_port: [invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}
