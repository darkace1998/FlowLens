package storage

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
)

func newTestSQLite(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteStore(dbPath, 1*time.Hour, 10*time.Minute)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	return store
}

func TestSQLiteStore_InsertAndRecent(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	now := time.Now().UTC()
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 1234, 80, now.Add(-5*time.Minute)),
		makeTestFlow("10.0.1.2", "192.168.1.2", 1235, 443, now.Add(-1*time.Minute)),
		makeTestFlow("10.0.1.3", "192.168.1.3", 1236, 8080, now),
	}

	if err := store.Insert(flows); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	recent, err := store.Recent(10*time.Minute, 0)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}

	if len(recent) != 3 {
		t.Fatalf("Recent(10m) returned %d records, want 3", len(recent))
	}

	// Most recent first.
	if recent[0].SrcPort != 1236 {
		t.Errorf("recent[0].SrcPort = %d, want 1236 (most recent)", recent[0].SrcPort)
	}
	if recent[2].SrcPort != 1234 {
		t.Errorf("recent[2].SrcPort = %d, want 1234 (oldest)", recent[2].SrcPort)
	}
}

func TestSQLiteStore_RecentWithLimit(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	now := time.Now().UTC()
	var flows []model.Flow
	for i := 0; i < 10; i++ {
		flows = append(flows, makeTestFlow("10.0.1.1", "192.168.1.1", uint16(1000+i), 80,
			now.Add(-time.Duration(i)*time.Minute)))
	}

	if err := store.Insert(flows); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	recent, err := store.Recent(time.Hour, 3)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}

	if len(recent) != 3 {
		t.Errorf("Recent(1h, limit=3) returned %d records, want 3", len(recent))
	}
}

func TestSQLiteStore_RecordFields(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second) // SQLite datetime precision
	f := model.Flow{
		Timestamp:   now,
		SrcAddr:     net.ParseIP("10.0.1.50"),
		DstAddr:     net.ParseIP("192.168.1.100"),
		SrcPort:     54321,
		DstPort:     443,
		Protocol:    6,
		Bytes:       65536,
		Packets:     42,
		TCPFlags:    0x12,
		ToS:         4,
		InputIface:  1,
		OutputIface: 2,
		SrcAS:       65000,
		DstAS:       65001,
		Duration:    5 * time.Second,
		ExporterIP:  net.ParseIP("172.16.0.1"),
	}
	f.Classify()

	if err := store.Insert([]model.Flow{f}); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	recent, err := store.Recent(time.Hour, 0)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(recent))
	}

	got := recent[0]

	if !got.SrcAddr.Equal(net.ParseIP("10.0.1.50")) {
		t.Errorf("SrcAddr = %s, want 10.0.1.50", got.SrcAddr)
	}
	if !got.DstAddr.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("DstAddr = %s, want 192.168.1.100", got.DstAddr)
	}
	if got.SrcPort != 54321 {
		t.Errorf("SrcPort = %d, want 54321", got.SrcPort)
	}
	if got.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", got.DstPort)
	}
	if got.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6", got.Protocol)
	}
	if got.Bytes != 65536 {
		t.Errorf("Bytes = %d, want 65536", got.Bytes)
	}
	if got.Packets != 42 {
		t.Errorf("Packets = %d, want 42", got.Packets)
	}
	if got.TCPFlags != 0x12 {
		t.Errorf("TCPFlags = 0x%02x, want 0x12", got.TCPFlags)
	}
	if got.ToS != 4 {
		t.Errorf("ToS = %d, want 4", got.ToS)
	}
	if got.InputIface != 1 {
		t.Errorf("InputIface = %d, want 1", got.InputIface)
	}
	if got.OutputIface != 2 {
		t.Errorf("OutputIface = %d, want 2", got.OutputIface)
	}
	if got.SrcAS != 65000 {
		t.Errorf("SrcAS = %d, want 65000", got.SrcAS)
	}
	if got.DstAS != 65001 {
		t.Errorf("DstAS = %d, want 65001", got.DstAS)
	}
	if got.Duration != 5*time.Second {
		t.Errorf("Duration = %s, want 5s", got.Duration)
	}
	if !got.ExporterIP.Equal(net.ParseIP("172.16.0.1")) {
		t.Errorf("ExporterIP = %s, want 172.16.0.1", got.ExporterIP)
	}
	if got.AppProto != "HTTPS" {
		t.Errorf("AppProto = %q, want HTTPS", got.AppProto)
	}
	if got.AppCat != "Web" {
		t.Errorf("AppCat = %q, want Web", got.AppCat)
	}
}

func TestSQLiteStore_Prune(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	now := time.Now().UTC()
	// Override retention to a short window for testing.
	store.retention = 5 * time.Minute

	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 1000, 80, now.Add(-10*time.Minute)), // should be pruned
		makeTestFlow("10.0.1.2", "192.168.1.2", 1001, 80, now.Add(-1*time.Minute)),  // should remain
		makeTestFlow("10.0.1.3", "192.168.1.3", 1002, 80, now),                       // should remain
	}

	if err := store.Insert(flows); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	deleted, err := store.Prune()
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}

	if deleted != 1 {
		t.Errorf("Prune deleted %d records, want 1", deleted)
	}

	// Verify remaining records.
	recent, err := store.Recent(time.Hour, 0)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}
	if len(recent) != 2 {
		t.Errorf("after prune, Recent(1h) returned %d records, want 2", len(recent))
	}
}

func TestSQLiteStore_RecentTimeFilter(t *testing.T) {
	store := newTestSQLite(t)
	defer store.Close()

	now := time.Now().UTC()
	flows := []model.Flow{
		makeTestFlow("10.0.1.1", "192.168.1.1", 1000, 80, now.Add(-30*time.Minute)),
		makeTestFlow("10.0.1.2", "192.168.1.2", 1001, 80, now.Add(-5*time.Minute)),
		makeTestFlow("10.0.1.3", "192.168.1.3", 1002, 80, now),
	}

	if err := store.Insert(flows); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	recent, err := store.Recent(10*time.Minute, 0)
	if err != nil {
		t.Fatalf("Recent failed: %v", err)
	}

	if len(recent) != 2 {
		t.Errorf("Recent(10m) returned %d records, want 2", len(recent))
	}
}

func TestSQLiteStore_Close(t *testing.T) {
	store := newTestSQLite(t)
	err := store.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}
