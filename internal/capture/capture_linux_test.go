//go:build linux

package capture

import (
	"strings"
	"testing"

	"github.com/darkace1998/FlowLens/internal/config"
)

func TestStartCapture_InvalidInterface(t *testing.T) {
	cfg := config.InterfaceConfig{
		Name:   "test-invalid",
		Type:   "mirror",
		Device: "invalid-eth0",
	}
	src := NewSource(cfg, nil)

	err := src.startCapture(cfg.Device, 65535)
	if err == nil {
		t.Fatal("expected error for invalid interface, got nil")
	}

	if !strings.Contains(err.Error(), "invalid-eth0") {
		t.Errorf("expected error to contain 'invalid-eth0', got: %v", err)
	}
}

func TestStartCapture_InvalidBPF(t *testing.T) {
	// "lo" always exists; the invalid filter must be rejected (and the socket
	// closed) before the read loop starts.
	cfg := config.InterfaceConfig{
		Name:   "test-bpf",
		Type:   "mirror",
		Device: "lo",
		BPF:    "tcp port", // invalid: missing port value
	}
	src := NewSource(cfg, nil)

	err := src.startCapture(cfg.Device, 65535)
	if err == nil {
		t.Fatal("expected error for invalid BPF filter, got nil")
	}
	if !strings.Contains(err.Error(), "invalid BPF filter") {
		t.Errorf("expected error to mention 'invalid BPF filter', got: %v", err)
	}
	if !strings.Contains(err.Error(), "lo") {
		t.Errorf("expected error to contain device name 'lo', got: %v", err)
	}
}
