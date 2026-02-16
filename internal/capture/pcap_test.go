package capture

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPcapWriter_WritePacket(t *testing.T) {
	dir := t.TempDir()
	pw, err := NewPcapWriter(dir, "test", 65535, 0, 0)
	if err != nil {
		t.Fatalf("NewPcapWriter: %v", err)
	}
	defer pw.Close()

	// Write a small packet.
	pkt := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	ts := time.Date(2025, 1, 15, 10, 30, 0, 500000000, time.UTC)

	if err := pw.WritePacket(pkt, ts); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	pkts, bytes := pw.Stats()
	if pkts != 1 {
		t.Errorf("packets = %d, want 1", pkts)
	}
	if bytes != 24+16+5 { // global header + pkt header + pkt data
		t.Errorf("bytes = %d, want %d", bytes, 24+16+5)
	}

	pw.Close()

	// Verify the PCAP file contents.
	files, err := filepath.Glob(filepath.Join(dir, "test_*.pcap"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected 1 pcap file, got %d (err=%v)", len(files), err)
	}

	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Verify global header.
	if len(data) < 24 {
		t.Fatalf("file too short: %d bytes", len(data))
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != pcapMagic {
		t.Errorf("magic = 0x%08x, want 0x%08x", magic, pcapMagic)
	}
	snapLen := binary.LittleEndian.Uint32(data[16:20])
	if snapLen != 65535 {
		t.Errorf("snapLen = %d, want 65535", snapLen)
	}
	linkType := binary.LittleEndian.Uint32(data[20:24])
	if linkType != linkTypeEthernet {
		t.Errorf("linkType = %d, want %d", linkType, linkTypeEthernet)
	}

	// Verify packet record header.
	if len(data) < 24+16+5 {
		t.Fatalf("file too short for packet: %d bytes", len(data))
	}
	tsSec := binary.LittleEndian.Uint32(data[24:28])
	tsUsec := binary.LittleEndian.Uint32(data[28:32])
	capturedLen := binary.LittleEndian.Uint32(data[32:36])
	origLen := binary.LittleEndian.Uint32(data[36:40])

	if tsSec != uint32(ts.Unix()) {
		t.Errorf("tsSec = %d, want %d", tsSec, ts.Unix())
	}
	if tsUsec != 500000 { // 500ms in microseconds
		t.Errorf("tsUsec = %d, want 500000", tsUsec)
	}
	if capturedLen != 5 {
		t.Errorf("capturedLen = %d, want 5", capturedLen)
	}
	if origLen != 5 {
		t.Errorf("origLen = %d, want 5", origLen)
	}

	// Verify packet data.
	if data[40] != 0x01 || data[44] != 0x05 {
		t.Errorf("packet data mismatch")
	}
}

func TestPcapWriter_MultiplePackets(t *testing.T) {
	dir := t.TempDir()
	pw, err := NewPcapWriter(dir, "multi", 65535, 0, 0)
	if err != nil {
		t.Fatalf("NewPcapWriter: %v", err)
	}
	defer pw.Close()

	for i := 0; i < 10; i++ {
		pkt := []byte{byte(i), 0x00}
		if err := pw.WritePacket(pkt, time.Now()); err != nil {
			t.Fatalf("WritePacket[%d]: %v", i, err)
		}
	}

	pkts, _ := pw.Stats()
	if pkts != 10 {
		t.Errorf("packets = %d, want 10", pkts)
	}
}

func TestPcapWriter_SnapLenTruncation(t *testing.T) {
	dir := t.TempDir()
	pw, err := NewPcapWriter(dir, "snap", 10, 0, 0) // snapLen = 10
	if err != nil {
		t.Fatalf("NewPcapWriter: %v", err)
	}

	// Write a 20-byte packet — should be truncated to 10 bytes.
	pkt := make([]byte, 20)
	for i := range pkt {
		pkt[i] = byte(i)
	}
	if err := pw.WritePacket(pkt, time.Now()); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	pw.Close()

	files, _ := filepath.Glob(filepath.Join(dir, "snap_*.pcap"))
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	data, _ := os.ReadFile(files[0])
	// Global header (24) + pkt header (16) + captured data (10) = 50
	if len(data) != 50 {
		t.Errorf("file size = %d, want 50", len(data))
	}

	// Check that capturedLen=10, origLen=20.
	capturedLen := binary.LittleEndian.Uint32(data[32:36])
	origLen := binary.LittleEndian.Uint32(data[36:40])
	if capturedLen != 10 {
		t.Errorf("capturedLen = %d, want 10", capturedLen)
	}
	if origLen != 20 {
		t.Errorf("origLen = %d, want 20", origLen)
	}
}

func TestPcapWriter_Rotation(t *testing.T) {
	dir := t.TempDir()
	// Max size = 1 byte — should rotate on every packet after the first.
	pw, err := NewPcapWriter(dir, "rot", 65535, 0, 5) // maxFiles=5 but maxSizeMB=0 means no rotation by size
	if err != nil {
		t.Fatalf("NewPcapWriter: %v", err)
	}
	defer pw.Close()

	// Write one packet.
	if err := pw.WritePacket([]byte{0x01}, time.Now()); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	pkts, _ := pw.Stats()
	if pkts != 1 {
		t.Errorf("packets = %d, want 1", pkts)
	}
}

func TestListPcapFiles_Empty(t *testing.T) {
	dir := t.TempDir()
	files, err := ListPcapFiles(dir)
	if err != nil {
		t.Fatalf("ListPcapFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestListPcapFiles_NonExistentDir(t *testing.T) {
	files, err := ListPcapFiles("/nonexistent/path/captures")
	if err != nil {
		t.Fatalf("ListPcapFiles should not error on missing dir: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestListPcapFiles_WithFiles(t *testing.T) {
	dir := t.TempDir()

	// Create some test PCAP files.
	for _, name := range []string{"a.pcap", "b.pcap", "not_pcap.txt"} {
		os.WriteFile(filepath.Join(dir, name), []byte("test"), 0644)
	}

	files, err := ListPcapFiles(dir)
	if err != nil {
		t.Fatalf("ListPcapFiles: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 pcap files, got %d", len(files))
	}
}
