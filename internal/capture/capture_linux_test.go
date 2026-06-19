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
