package capture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/darkace1998/FlowLens/internal/config"
)

func TestNewManager(t *testing.T) {
	cfg := config.CaptureConfig{
		Interfaces: []string{"eth0", "eth1"},
		SnapLen:    65535,
		Dir:        t.TempDir(),
		MaxSizeMB:  100,
		MaxFiles:   10,
	}

	m := NewManager(cfg)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if len(m.Interfaces()) != 2 {
		t.Errorf("Interfaces() = %d, want 2", len(m.Interfaces()))
	}
}

func TestManager_Sessions_Empty(t *testing.T) {
	cfg := config.CaptureConfig{Dir: t.TempDir()}
	m := NewManager(cfg)

	sessions := m.Sessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestManager_PcapDir(t *testing.T) {
	dir := t.TempDir()
	cfg := config.CaptureConfig{Dir: dir}
	m := NewManager(cfg)

	if m.PcapDir() != dir {
		t.Errorf("PcapDir() = %q, want %q", m.PcapDir(), dir)
	}
}

func TestManager_PcapFiles_Empty(t *testing.T) {
	cfg := config.CaptureConfig{Dir: t.TempDir()}
	m := NewManager(cfg)

	files, err := m.PcapFiles()
	if err != nil {
		t.Fatalf("PcapFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestManager_PcapFilePath_Valid(t *testing.T) {
	dir := t.TempDir()
	cfg := config.CaptureConfig{Dir: dir}
	m := NewManager(cfg)

	// Create a test PCAP file.
	testFile := filepath.Join(dir, "test.pcap")
	os.WriteFile(testFile, []byte("pcap data"), 0644)

	path, err := m.PcapFilePath("test.pcap")
	if err != nil {
		t.Fatalf("PcapFilePath: %v", err)
	}
	if path != testFile {
		t.Errorf("PcapFilePath = %q, want %q", path, testFile)
	}
}

func TestManager_PcapFilePath_Invalid(t *testing.T) {
	cfg := config.CaptureConfig{Dir: t.TempDir()}
	m := NewManager(cfg)

	// Non-existent file.
	_, err := m.PcapFilePath("nonexistent.pcap")
	if err == nil {
		t.Error("PcapFilePath should error for non-existent file")
	}

	// Path traversal attempt.
	_, err = m.PcapFilePath("../../etc/passwd")
	if err == nil {
		t.Error("PcapFilePath should reject path traversal")
	}
}

func TestManager_StopNonExistent(t *testing.T) {
	cfg := config.CaptureConfig{Dir: t.TempDir()}
	m := NewManager(cfg)

	err := m.Stop("nonexistent")
	if err == nil {
		t.Error("Stop should error for non-existent session")
	}
}
