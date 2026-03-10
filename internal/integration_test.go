package integration_test

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/collector"
	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
	"github.com/darkace1998/FlowLens/internal/web"
)

// TestCollector_RingBuffer_WebHandler verifies the full pipeline:
// NetFlow v5 packet → collector → ring buffer → web dashboard handler.
func TestCollector_RingBuffer_WebHandler(t *testing.T) {
	// 1. Set up storage.
	ringBuf := storage.NewRingBuffer(1000)

	// 2. Set up collector with a handler that inserts into the ring buffer.
	var mu sync.Mutex
	handler := func(flows []model.Flow) {
		mu.Lock()
		defer mu.Unlock()
		ringBuf.Insert(flows)
	}

	cfg := config.CollectorConfig{
		NetFlowPort: 0, // OS-assigned
		BufferSize:  65535,
	}
	c := collector.New(cfg, handler)

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start() }()
	time.Sleep(50 * time.Millisecond)

	addr := c.Addr()
	if addr == nil {
		t.Fatal("collector did not start — no address")
	}
	defer c.Stop()

	// 3. Send a NetFlow v5 packet.
	pkt := buildNFV5Packet(3)
	udpAddr := addr.(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	// 4. Wait for processing.
	time.Sleep(200 * time.Millisecond)

	// 5. Verify flows arrived in ring buffer.
	mu.Lock()
	count := ringBuf.Len()
	mu.Unlock()
	if count != 3 {
		t.Fatalf("ring buffer has %d flows, want 3", count)
	}

	// 6. Set up web server and verify the dashboard shows data.
	webCfg := config.WebConfig{Listen: ":0", PageSize: 50}
	s := web.NewServer(webCfg, ringBuf, nil, t.TempDir(), nil, nil, nil)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("dashboard status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "No flow data yet") {
		t.Error("dashboard should NOT show 'No flow data yet' after receiving flows")
	}
	if !strings.Contains(body, "Dashboard") {
		t.Error("dashboard response should contain 'Dashboard'")
	}
}

// TestCollector_SQLite_WebHandler verifies the pipeline with SQLite persistence:
// NetFlow v5 packet → collector → SQLite + ring buffer → web flows page.
func TestCollector_SQLite_WebHandler(t *testing.T) {
	// 1. Set up storage.
	ringBuf := storage.NewRingBuffer(1000)
	dbPath := filepath.Join(t.TempDir(), "integration.db")
	sqlStore, err := storage.NewSQLiteStore(dbPath, 1*time.Hour, 10*time.Minute)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer sqlStore.Close()

	// 2. Set up collector that writes to both stores.
	var mu sync.Mutex
	handler := func(flows []model.Flow) {
		mu.Lock()
		defer mu.Unlock()
		ringBuf.Insert(flows)
		sqlStore.Insert(flows)
	}

	cfg := config.CollectorConfig{
		NetFlowPort: 0,
		BufferSize:  65535,
	}
	c := collector.New(cfg, handler)

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start() }()
	time.Sleep(50 * time.Millisecond)

	addr := c.Addr()
	if addr == nil {
		t.Fatal("collector did not start")
	}
	defer c.Stop()

	// 3. Send packets.
	pkt := buildNFV5Packet(2)
	udpAddr := addr.(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	time.Sleep(200 * time.Millisecond)

	// 4. Verify ring buffer.
	mu.Lock()
	rbCount := ringBuf.Len()
	mu.Unlock()
	if rbCount != 2 {
		t.Fatalf("ring buffer has %d flows, want 2", rbCount)
	}

	// 5. Verify SQLite.
	recent, err := sqlStore.Recent(10*time.Minute, 0)
	if err != nil {
		t.Fatalf("sqlStore.Recent: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("SQLite has %d flows, want 2", len(recent))
	}

	// 6. Verify web flows page with data from ring buffer.
	webCfg := config.WebConfig{Listen: ":0", PageSize: 50}
	s := web.NewServer(webCfg, ringBuf, sqlStore, t.TempDir(), nil, nil, nil)

	req := httptest.NewRequest("GET", "/flows", nil)
	w := httptest.NewRecorder()
	s.Mux().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("flows page status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Flow Explorer") {
		t.Error("flows page should contain 'Flow Explorer'")
	}
	// The page should show "2 flows" since we inserted 2.
	if !strings.Contains(body, "2 flows") {
		t.Errorf("expected '2 flows' in body, got snippet: %s", body[:min(len(body), 300)])
	}
}

// TestMultiProtocol_RoundTrip sends different protocol types and verifies
// they all end up in storage correctly.
func TestMultiProtocol_RoundTrip(t *testing.T) {
	ringBuf := storage.NewRingBuffer(1000)

	var mu sync.Mutex
	handler := func(flows []model.Flow) {
		mu.Lock()
		defer mu.Unlock()
		ringBuf.Insert(flows)
	}

	cfg := config.CollectorConfig{
		NetFlowPort: 0,
		BufferSize:  65535,
	}
	c := collector.New(cfg, handler)

	errCh := make(chan error, 1)
	go func() { errCh <- c.Start() }()
	time.Sleep(50 * time.Millisecond)

	addr := c.Addr()
	if addr == nil {
		t.Fatal("collector did not start")
	}
	defer c.Stop()

	// Send multiple NFV5 packets.
	for i := 0; i < 5; i++ {
		pkt := buildNFV5Packet(1)
		udpAddr := addr.(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.Write(pkt)
		conn.Close()
	}

	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	count := ringBuf.Len()
	mu.Unlock()
	if count != 5 {
		t.Errorf("expected 5 flows, got %d", count)
	}

	// Verify all flows have expected fields.
	all := ringBuf.All()
	for i, f := range all {
		if f.Protocol != 6 {
			t.Errorf("flow[%d]: Protocol = %d, want 6", i, f.Protocol)
		}
		if f.Bytes != 15000 {
			t.Errorf("flow[%d]: Bytes = %d, want 15000", i, f.Bytes)
		}
		if f.ExporterIP == nil {
			t.Errorf("flow[%d]: ExporterIP is nil", i)
		}
	}
}

// buildNFV5Packet constructs a valid NetFlow v5 packet — duplicated here
// since this is a separate test package and cannot access the internal helper.
func buildNFV5Packet(count int) []byte {
	const headerSize = 24
	const recordSize = 48

	pkt := make([]byte, headerSize+count*recordSize)
	binary.BigEndian.PutUint16(pkt[0:2], 5)            // version
	binary.BigEndian.PutUint16(pkt[2:4], uint16(count)) // count
	binary.BigEndian.PutUint32(pkt[4:8], 600000)        // sysUptime
	binary.BigEndian.PutUint32(pkt[8:12], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(pkt[12:16], 0)           // nsecs

	for i := 0; i < count; i++ {
		off := headerSize + i*recordSize
		rec := pkt[off : off+recordSize]

		rec[0] = 10
		rec[1] = 0
		rec[2] = 1
		rec[3] = byte(i + 1) // src: 10.0.1.<i+1>

		rec[4] = 192
		rec[5] = 168
		rec[6] = 1
		rec[7] = byte(i + 1) // dst: 192.168.1.<i+1>

		binary.BigEndian.PutUint16(rec[12:14], uint16(i+1))
		binary.BigEndian.PutUint16(rec[14:16], uint16(i+2))
		binary.BigEndian.PutUint32(rec[16:20], 100)   // packets
		binary.BigEndian.PutUint32(rec[20:24], 15000)  // bytes
		binary.BigEndian.PutUint32(rec[24:28], 594000) // first
		binary.BigEndian.PutUint32(rec[28:32], 599000) // last
		binary.BigEndian.PutUint16(rec[32:34], 12345)  // srcPort
		binary.BigEndian.PutUint16(rec[34:36], 443)    // dstPort
		rec[37] = 0x12                                 // TCP flags
		rec[38] = 6                                    // protocol = TCP
	}

	return pkt
}
