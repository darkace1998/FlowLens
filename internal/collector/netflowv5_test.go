package collector

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildNFV5Packet constructs a valid NetFlow v5 packet with the given number of records.
// Each record has predictable test values based on its index.
func buildNFV5Packet(count int) []byte {
	pkt := make([]byte, nfv5HeaderSize+count*nfv5RecordSize)

	// Header
	binary.BigEndian.PutUint16(pkt[0:2], 5)            // version
	binary.BigEndian.PutUint16(pkt[2:4], uint16(count)) // count
	binary.BigEndian.PutUint32(pkt[4:8], 600000)        // sysUptime (600s = 10 min)
	binary.BigEndian.PutUint32(pkt[8:12], 1700000000)   // unixSecs
	binary.BigEndian.PutUint32(pkt[12:16], 0)           // unixNsecs
	binary.BigEndian.PutUint32(pkt[16:20], 42)          // flowSequence
	pkt[20] = 1                                         // engineType
	pkt[21] = 0                                         // engineID

	for i := 0; i < count; i++ {
		off := nfv5HeaderSize + i*nfv5RecordSize
		rec := pkt[off : off+nfv5RecordSize]

		// srcAddr: 10.0.1.<i+1>
		rec[0] = 10
		rec[1] = 0
		rec[2] = 1
		rec[3] = byte(i + 1)

		// dstAddr: 192.168.1.<i+1>
		rec[4] = 192
		rec[5] = 168
		rec[6] = 1
		rec[7] = byte(i + 1)

		// nextHop: 10.0.0.1
		rec[8] = 10
		rec[9] = 0
		rec[10] = 0
		rec[11] = 1

		binary.BigEndian.PutUint16(rec[12:14], uint16(i+1)) // input iface
		binary.BigEndian.PutUint16(rec[14:16], uint16(i+2)) // output iface
		binary.BigEndian.PutUint32(rec[16:20], 100)         // packets
		binary.BigEndian.PutUint32(rec[20:24], 15000)       // bytes

		// First/Last sysUptime: flow lasted 5 seconds, ending 1 second ago
		binary.BigEndian.PutUint32(rec[24:28], 594000) // first (594s)
		binary.BigEndian.PutUint32(rec[28:32], 599000) // last (599s)

		binary.BigEndian.PutUint16(rec[32:34], 12345)  // srcPort
		binary.BigEndian.PutUint16(rec[34:36], 443)    // dstPort
		rec[37] = 0x12                                 // tcpFlags (SYN+ACK)
		rec[38] = 6                                    // protocol (TCP)
		rec[39] = 0                                    // tos

		binary.BigEndian.PutUint16(rec[40:42], 65000) // srcAS
		binary.BigEndian.PutUint16(rec[42:44], 65001) // dstAS
		rec[44] = 24                                  // srcMask
		rec[45] = 24                                  // dstMask
	}

	return pkt
}

func TestDecodeNetFlowV5_SingleRecord(t *testing.T) {
	pkt := buildNFV5Packet(1)
	exporterIP := net.ParseIP("172.16.0.1")

	flows, err := DecodeNetFlowV5(pkt, exporterIP)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	f := flows[0]

	if !f.SrcAddr.Equal(net.ParseIP("10.0.1.1")) {
		t.Errorf("SrcAddr = %s, want 10.0.1.1", f.SrcAddr)
	}
	if !f.DstAddr.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("DstAddr = %s, want 192.168.1.1", f.DstAddr)
	}
	if f.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", f.SrcPort)
	}
	if f.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", f.DstPort)
	}
	if f.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", f.Protocol)
	}
	if f.Bytes != 15000 {
		t.Errorf("Bytes = %d, want 15000", f.Bytes)
	}
	if f.Packets != 100 {
		t.Errorf("Packets = %d, want 100", f.Packets)
	}
	if f.TCPFlags != 0x12 {
		t.Errorf("TCPFlags = 0x%02x, want 0x12", f.TCPFlags)
	}
	if f.InputIface != 1 {
		t.Errorf("InputIface = %d, want 1", f.InputIface)
	}
	if f.OutputIface != 2 {
		t.Errorf("OutputIface = %d, want 2", f.OutputIface)
	}
	if f.SrcAS != 65000 {
		t.Errorf("SrcAS = %d, want 65000", f.SrcAS)
	}
	if f.DstAS != 65001 {
		t.Errorf("DstAS = %d, want 65001", f.DstAS)
	}

	// Duration should be 5 seconds (599000 - 594000 ms)
	if f.Duration != 5*time.Second {
		t.Errorf("Duration = %s, want 5s", f.Duration)
	}

	if !f.ExporterIP.Equal(exporterIP) {
		t.Errorf("ExporterIP = %s, want %s", f.ExporterIP, exporterIP)
	}

	// Classify should have been called by the decoder.
	if f.AppProto != "HTTPS" {
		t.Errorf("AppProto = %q, want HTTPS", f.AppProto)
	}
	if f.AppCat != "Web" {
		t.Errorf("AppCat = %q, want Web", f.AppCat)
	}
}

func TestDecodeNetFlowV5_MultipleRecords(t *testing.T) {
	pkt := buildNFV5Packet(5)
	flows, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(flows) != 5 {
		t.Fatalf("expected 5 flows, got %d", len(flows))
	}

	// Check that each flow has a unique source address
	for i, f := range flows {
		wantLastOctet := byte(i + 1)
		srcBytes := f.SrcAddr.To4()
		if srcBytes == nil {
			t.Errorf("flow[%d] SrcAddr.To4() returned nil", i)
			continue
		}
		if srcBytes[3] != wantLastOctet {
			t.Errorf("flow[%d] SrcAddr last octet = %d, want %d", i, srcBytes[3], wantLastOctet)
		}
	}
}

func TestDecodeNetFlowV5_TooShortForHeader(t *testing.T) {
	data := make([]byte, 10) // less than 24-byte header
	_, err := DecodeNetFlowV5(data, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("expected error for short packet, got nil")
	}
}

func TestDecodeNetFlowV5_WrongVersion(t *testing.T) {
	pkt := buildNFV5Packet(1)
	binary.BigEndian.PutUint16(pkt[0:2], 9) // set version to 9
	_, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
}

func TestDecodeNetFlowV5_ZeroCount(t *testing.T) {
	pkt := buildNFV5Packet(1)
	binary.BigEndian.PutUint16(pkt[2:4], 0) // set count to 0
	_, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("expected error for zero count, got nil")
	}
}

func TestDecodeNetFlowV5_TruncatedRecords(t *testing.T) {
	pkt := buildNFV5Packet(1)
	// Truncate: claim 2 records but only provide data for 1
	binary.BigEndian.PutUint16(pkt[2:4], 2)
	_, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Fatal("expected error for truncated records, got nil")
	}
}

func TestDecodeNetFlowV5_Timestamp(t *testing.T) {
	pkt := buildNFV5Packet(1)
	flows, err := DecodeNetFlowV5(pkt, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Header: unixSecs=1700000000, sysUptime=600000ms
	// Record: last=599000ms
	// So flow ended 1 second before header time → timestamp = 1700000000 - 1 = 1699999999
	expected := time.Unix(1700000000, 0).Add(-1 * time.Second)
	if !flows[0].Timestamp.Equal(expected) {
		t.Errorf("Timestamp = %v, want %v", flows[0].Timestamp, expected)
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		input uint32
		want  string
	}{
		{0x0A000101, "10.0.1.1"},
		{0xC0A80101, "192.168.1.1"},
		{0xFFFFFFFF, "255.255.255.255"},
		{0x00000000, "0.0.0.0"},
	}
	for _, tt := range tests {
		got := uint32ToIP(tt.input)
		if got.String() != tt.want {
			t.Errorf("uint32ToIP(0x%08X) = %s, want %s", tt.input, got, tt.want)
		}
	}
}
