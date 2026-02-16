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

func TestCollector_DualPort_IPFIXOnSeparatePort(t *testing.T) {
	var mu sync.Mutex
	var received []model.Flow

	handler := func(flows []model.Flow) {
		mu.Lock()
		received = append(received, flows...)
		mu.Unlock()
	}

	// Find two free ports by briefly listening on port 0.
	l1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port1 := l1.LocalAddr().(*net.UDPAddr).Port
	l1.Close()

	l2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port2 := l2.LocalAddr().(*net.UDPAddr).Port
	l2.Close()

	cfg := config.CollectorConfig{
		NetFlowPort: port1,
		IPFIXPort:   port2,
		BufferSize:  65535,
	}

	c := New(cfg, handler)

	go func() {
		_ = c.Start()
	}()

	time.Sleep(100 * time.Millisecond)

	addrs := c.Addrs()
	if len(addrs) < 2 {
		t.Fatalf("expected 2 listeners, got %d", len(addrs))
	}
	defer c.Stop()

	netflowPort := addrs[0].(*net.UDPAddr).Port
	ipfixPort := addrs[1].(*net.UDPAddr).Port

	if netflowPort == ipfixPort {
		t.Fatalf("expected different ports, got same port %d", netflowPort)
	}

	// Send NetFlow v9 to the NetFlow port.
	nfv9Fields := standardNFV9Fields()
	nfv9Tmpl := buildNFV9TemplateFlowSet(256, nfv9Fields)
	nfv9Rec := buildNFV9RecordData(
		net.ParseIP("10.1.0.1"), net.ParseIP("10.2.0.1"),
		8080, 80, 17, 5000, 50, 0, 0,
		3, 4, 200, 300, 590000, 599000,
	)
	nfv9Data := buildNFV9DataFlowSet(256, nfv9Rec)
	v9Pkt := buildNFV9Packet(1, 600000, 1700000000, nfv9Tmpl, nfv9Data)

	nfConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: netflowPort,
	})
	if err != nil {
		t.Fatalf("failed to dial NetFlow port: %v", err)
	}
	defer nfConn.Close()
	if _, err := nfConn.Write(v9Pkt); err != nil {
		t.Fatalf("failed to send v9 packet: %v", err)
	}

	// Send IPFIX to the IPFIX port.
	ipfixFields := standardIPFIXFields()
	ipfixTmpl := buildIPFIXTemplateSet(256, ipfixFields)
	ipfixRec := buildIPFIXRecordData(
		net.ParseIP("10.3.0.1"), net.ParseIP("10.4.0.1"),
		9090, 443, 6, 25000, 200, 0x10, 0,
		5, 6, 400, 500,
	)
	ipfixData := buildIPFIXDataSet(256, ipfixRec)
	ipfixPkt := buildIPFIXPacket(1, 1700000000, ipfixTmpl, ipfixData)

	ipfixConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: ipfixPort,
	})
	if err != nil {
		t.Fatalf("failed to dial IPFIX port: %v", err)
	}
	defer ipfixConn.Close()
	if _, err := ipfixConn.Write(ipfixPkt); err != nil {
		t.Fatalf("failed to send IPFIX packet: %v", err)
	}

	// Wait for both flows to be received.
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		count := len(received)
		mu.Unlock()
		if count >= 2 {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			t.Fatalf("timed out waiting for flows; received %d, want 2", len(received))
			mu.Unlock()
		case <-time.After(10 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 2 {
		t.Fatalf("expected 2 flows (v9 on netflow port + IPFIX on ipfix port), got %d", len(received))
	}
}

func TestCollector_MixedV5V9IPFIX(t *testing.T) {
	var mu sync.Mutex
	var received []model.Flow

	handler := func(flows []model.Flow) {
		mu.Lock()
		received = append(received, flows...)
		mu.Unlock()
	}

	cfg := config.CollectorConfig{
		NetFlowPort: 0,
		BufferSize:  65535,
	}

	c := New(cfg, handler)

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	addr := c.Addr()
	if addr == nil {
		t.Fatal("collector did not start listening")
	}
	assignedPort := addr.(*net.UDPAddr).Port
	defer c.Stop()

	sendConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: assignedPort,
	})
	if err != nil {
		t.Fatalf("failed to dial UDP: %v", err)
	}
	defer sendConn.Close()

	// 1. Send a NetFlow v5 packet (1 flow)
	v5Pkt := buildNFV5Packet(1)
	if _, err := sendConn.Write(v5Pkt); err != nil {
		t.Fatalf("failed to send v5 packet: %v", err)
	}

	// 2. Send NetFlow v9: template first, then data (1 flow)
	nfv9Fields := standardNFV9Fields()
	nfv9Tmpl := buildNFV9TemplateFlowSet(256, nfv9Fields)
	nfv9Rec := buildNFV9RecordData(
		net.ParseIP("10.1.0.1"), net.ParseIP("10.2.0.1"),
		8080, 80, 17, 5000, 50, 0, 0,
		3, 4, 200, 300, 590000, 599000,
	)
	nfv9Data := buildNFV9DataFlowSet(256, nfv9Rec)
	v9Pkt := buildNFV9Packet(1, 600000, 1700000000, nfv9Tmpl, nfv9Data)
	if _, err := sendConn.Write(v9Pkt); err != nil {
		t.Fatalf("failed to send v9 packet: %v", err)
	}

	// 3. Send IPFIX packet: template + data (1 flow)
	ipfixFields := standardIPFIXFields()
	ipfixTmpl := buildIPFIXTemplateSet(256, ipfixFields)
	ipfixRec := buildIPFIXRecordData(
		net.ParseIP("10.3.0.1"), net.ParseIP("10.4.0.1"),
		9090, 443, 6, 25000, 200, 0x10, 0,
		5, 6, 400, 500,
	)
	ipfixData := buildIPFIXDataSet(256, ipfixRec)
	ipfixPkt := buildIPFIXPacket(1, 1700000000, ipfixTmpl, ipfixData)
	if _, err := sendConn.Write(ipfixPkt); err != nil {
		t.Fatalf("failed to send IPFIX packet: %v", err)
	}

	// Wait for all 3 flows to be received
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		count := len(received)
		mu.Unlock()
		if count >= 3 {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			t.Fatalf("timed out waiting for flows; received %d, want 3", len(received))
			mu.Unlock()
		case <-time.After(10 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	if len(received) != 3 {
		t.Fatalf("expected 3 flows (v5+v9+IPFIX), got %d", len(received))
	}

	// Verify v5 flow
	if received[0].DstPort != 443 {
		t.Errorf("v5 flow DstPort = %d, want 443", received[0].DstPort)
	}

	// Verify v9 flow
	if !received[1].SrcAddr.Equal(net.ParseIP("10.1.0.1")) {
		t.Errorf("v9 flow SrcAddr = %s, want 10.1.0.1", received[1].SrcAddr)
	}
	if received[1].Protocol != 17 {
		t.Errorf("v9 flow Protocol = %d, want 17 (UDP)", received[1].Protocol)
	}

	// Verify IPFIX flow
	if !received[2].SrcAddr.Equal(net.ParseIP("10.3.0.1")) {
		t.Errorf("IPFIX flow SrcAddr = %s, want 10.3.0.1", received[2].SrcAddr)
	}
	if received[2].Bytes != 25000 {
		t.Errorf("IPFIX flow Bytes = %d, want 25000", received[2].Bytes)
	}
}
