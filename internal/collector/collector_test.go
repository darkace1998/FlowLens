package collector

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
)

func TestCollector_ReceivesFlows(t *testing.T) {
	var mu sync.Mutex
	var received []model.Flow

	handler := func(flows []model.Flow) {
		mu.Lock()
		received = append(received, flows...)
		mu.Unlock()
	}

	cfg := config.CollectorConfig{
		NetFlowPort: 0, // OS-assigned port
		BufferSize:  65535,
	}

	c := New(cfg, handler)

	// Start collector in background.
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start()
	}()

	// Wait briefly for the listener to be ready.
	time.Sleep(50 * time.Millisecond)

	addr := c.Addr()
	if addr == nil {
		t.Fatal("collector did not start listening")
	}
	assignedPort := addr.(*net.UDPAddr).Port
	defer c.Stop()

	// Send a NetFlow v5 packet to the collector.
	pkt := buildNFV5Packet(3)
	sendConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: assignedPort,
	})
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer sendConn.Close()

	_, err = sendConn.Write(pkt)
	if err != nil {
		t.Fatalf("failed to send packet: %v", err)
	}

	// Wait for the flows to be processed.
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		count := len(received)
		mu.Unlock()
		if count >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for flows; received %d, want 3", count)
		case <-time.After(10 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 3 {
		t.Fatalf("expected 3 flows, got %d", len(received))
	}

	// Verify first flow
	f := received[0]
	if f.Protocol != 6 {
		t.Errorf("flow[0].Protocol = %d, want 6", f.Protocol)
	}
	if f.DstPort != 443 {
		t.Errorf("flow[0].DstPort = %d, want 443", f.DstPort)
	}
}
