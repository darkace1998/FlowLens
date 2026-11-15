//go:build linux

package capture

import (
	"strings"
	"syscall"
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

// requireRawSocket skips the test when the environment cannot open AF_PACKET
// raw sockets (e.g. unprivileged CI runners without CAP_NET_RAW).
func requireRawSocket(t *testing.T) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err == nil {
		_ = syscall.Close(fd) // nolint:errcheck // probe socket, cleanup only
		return
	}
	if err == syscall.EPERM || err == syscall.EACCES {
		t.Skipf("skipping: AF_PACKET raw sockets unavailable (no CAP_NET_RAW): %v", err)
	}
	t.Fatalf("unexpected error probing AF_PACKET socket: %v", err)
}

func TestStartCapture_InvalidBPF(t *testing.T) {
	requireRawSocket(t)

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
