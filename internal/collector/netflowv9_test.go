package collector

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildNFV9TemplateFlowSet builds a Template FlowSet (ID 0) for the given template.
func buildNFV9TemplateFlowSet(templateID uint16, fields []nfv9TemplateField) []byte {
	// FlowSet header: 4 bytes (ID=0, length)
	// Template header: 4 bytes (templateID, fieldCount)
	// Fields: 4 bytes each
	bodyLen := 4 + len(fields)*4
	totalLen := 4 + bodyLen
	data := make([]byte, totalLen)

	binary.BigEndian.PutUint16(data[0:2], 0)              // FlowSet ID = Template
	binary.BigEndian.PutUint16(data[2:4], uint16(totalLen)) // FlowSet Length

	binary.BigEndian.PutUint16(data[4:6], templateID)
	binary.BigEndian.PutUint16(data[6:8], uint16(len(fields)))

	off := 8
	for _, f := range fields {
		binary.BigEndian.PutUint16(data[off:off+2], f.Type)
		binary.BigEndian.PutUint16(data[off+2:off+4], f.Length)
		off += 4
	}

	return data
}

// buildNFV9DataFlowSet builds a Data FlowSet with template ID and raw record data.
func buildNFV9DataFlowSet(templateID uint16, recordData []byte) []byte {
	totalLen := 4 + len(recordData)
	data := make([]byte, totalLen)
	binary.BigEndian.PutUint16(data[0:2], templateID)
	binary.BigEndian.PutUint16(data[2:4], uint16(totalLen))
	copy(data[4:], recordData)
	return data
}

// buildNFV9Packet assembles a complete NetFlow v9 packet from FlowSets.
func buildNFV9Packet(sourceID uint32, sysUptime uint32, unixSecs uint32, flowSets ...[]byte) []byte {
	bodyLen := 0
	for _, fs := range flowSets {
		bodyLen += len(fs)
	}

	pkt := make([]byte, nfv9HeaderSize+bodyLen)

	// Header
	binary.BigEndian.PutUint16(pkt[0:2], 9)               // version
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(flowSets))) // count (FlowSets)
	binary.BigEndian.PutUint32(pkt[4:8], sysUptime)
	binary.BigEndian.PutUint32(pkt[8:12], unixSecs)
	binary.BigEndian.PutUint32(pkt[12:16], 1)              // sequence
	binary.BigEndian.PutUint32(pkt[16:20], sourceID)

	off := nfv9HeaderSize
	for _, fs := range flowSets {
		copy(pkt[off:], fs)
		off += len(fs)
	}

	return pkt
}

// standardNFV9Fields returns a basic template with common flow fields.
func standardNFV9Fields() []nfv9TemplateField {
	return []nfv9TemplateField{
		{Type: nfv9FieldIPv4SrcAddr, Length: 4},
		{Type: nfv9FieldIPv4DstAddr, Length: 4},
		{Type: nfv9FieldL4SrcPort, Length: 2},
		{Type: nfv9FieldL4DstPort, Length: 2},
		{Type: nfv9FieldProtocol, Length: 1},
		{Type: nfv9FieldInBytes, Length: 4},
		{Type: nfv9FieldInPkts, Length: 4},
		{Type: nfv9FieldTCPFlags, Length: 1},
		{Type: nfv9FieldSrcTos, Length: 1},
		{Type: nfv9FieldInputSNMP, Length: 2},
		{Type: nfv9FieldOutputSNMP, Length: 2},
		{Type: nfv9FieldSrcAS, Length: 2},
		{Type: nfv9FieldDstAS, Length: 2},
		{Type: nfv9FieldFirstSwitched, Length: 4},
		{Type: nfv9FieldLastSwitched, Length: 4},
	}
}

// buildNFV9RecordData builds raw record data for one flow record matching standardNFV9Fields.
func buildNFV9RecordData(srcIP, dstIP net.IP, srcPort, dstPort uint16,
	proto uint8, bytes, packets uint32, tcpFlags, tos uint8,
	inputIf, outputIf, srcAS, dstAS uint16, first, last uint32) []byte {

	// Total: 4+4+2+2+1+4+4+1+1+2+2+2+2+4+4 = 39 bytes
	data := make([]byte, 39)
	off := 0

	copy(data[off:off+4], srcIP.To4())
	off += 4
	copy(data[off:off+4], dstIP.To4())
	off += 4
	binary.BigEndian.PutUint16(data[off:off+2], srcPort)
	off += 2
	binary.BigEndian.PutUint16(data[off:off+2], dstPort)
	off += 2
	data[off] = proto
	off++
	binary.BigEndian.PutUint32(data[off:off+4], bytes)
	off += 4
	binary.BigEndian.PutUint32(data[off:off+4], packets)
	off += 4
	data[off] = tcpFlags
	off++
	data[off] = tos
	off++
	binary.BigEndian.PutUint16(data[off:off+2], inputIf)
	off += 2
	binary.BigEndian.PutUint16(data[off:off+2], outputIf)
	off += 2
	binary.BigEndian.PutUint16(data[off:off+2], srcAS)
	off += 2
	binary.BigEndian.PutUint16(data[off:off+2], dstAS)
	off += 2
	binary.BigEndian.PutUint32(data[off:off+4], first)
	off += 4
	binary.BigEndian.PutUint32(data[off:off+4], last)

	return data
}

func TestDecodeNetFlowV9_TemplateAndData(t *testing.T) {
	cache := NewNFV9TemplateCache()
	exporterIP := net.ParseIP("172.16.0.1")

	fields := standardNFV9Fields()
	tmplFS := buildNFV9TemplateFlowSet(256, fields)

	recData := buildNFV9RecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0,
		1, 2, 65000, 65001,
		594000, 599000,
	)
	dataFS := buildNFV9DataFlowSet(256, recData)

	pkt := buildNFV9Packet(1, 600000, 1700000000, tmplFS, dataFS)

	flows, err := DecodeNetFlowV9(pkt, exporterIP, cache)
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
		t.Errorf("Protocol = %d, want 6", f.Protocol)
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

	// Duration: last - first = 599000 - 594000 = 5000ms = 5s
	if f.Duration != 5*time.Second {
		t.Errorf("Duration = %s, want 5s", f.Duration)
	}

	// Timestamp: baseTime - (sysUptime - last) = 1700000000 - (600000-599000)ms = 1700000000 - 1s
	expected := time.Unix(1700000000, 0).Add(-1 * time.Second)
	if !f.Timestamp.Equal(expected) {
		t.Errorf("Timestamp = %v, want %v", f.Timestamp, expected)
	}

	if !f.ExporterIP.Equal(exporterIP) {
		t.Errorf("ExporterIP = %s, want %s", f.ExporterIP, exporterIP)
	}
}

func TestDecodeNetFlowV9_MultipleRecords(t *testing.T) {
	cache := NewNFV9TemplateCache()

	fields := standardNFV9Fields()
	tmplFS := buildNFV9TemplateFlowSet(256, fields)

	// Build 3 records
	var allRecData []byte
	for i := 0; i < 3; i++ {
		rec := buildNFV9RecordData(
			net.IPv4(10, 0, 1, byte(i+1)), net.IPv4(192, 168, 1, byte(i+1)),
			uint16(10000+i), 80, 6, uint32(1000*(i+1)), uint32(10*(i+1)),
			0x02, 0, 1, 2, 100, 200, 590000, 599000,
		)
		allRecData = append(allRecData, rec...)
	}
	dataFS := buildNFV9DataFlowSet(256, allRecData)

	pkt := buildNFV9Packet(1, 600000, 1700000000, tmplFS, dataFS)

	flows, err := DecodeNetFlowV9(pkt, net.ParseIP("10.0.0.1"), cache)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(flows) != 3 {
		t.Fatalf("expected 3 flows, got %d", len(flows))
	}

	for i, f := range flows {
		wantLastOctet := byte(i + 1)
		srcBytes := f.SrcAddr.To4()
		if srcBytes == nil || srcBytes[3] != wantLastOctet {
			t.Errorf("flow[%d] SrcAddr last octet = %v, want %d", i, srcBytes, wantLastOctet)
		}
	}
}

func TestDecodeNetFlowV9_TemplateOnly(t *testing.T) {
	cache := NewNFV9TemplateCache()

	fields := standardNFV9Fields()
	tmplFS := buildNFV9TemplateFlowSet(256, fields)

	pkt := buildNFV9Packet(1, 600000, 1700000000, tmplFS)

	flows, err := DecodeNetFlowV9(pkt, net.ParseIP("10.0.0.1"), cache)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(flows) != 0 {
		t.Fatalf("expected 0 flows for template-only packet, got %d", len(flows))
	}

	// Verify template was cached
	tmpl := cache.get(1, 256)
	if tmpl == nil {
		t.Fatal("template was not cached")
	}
	if len(tmpl.Fields) != len(fields) {
		t.Errorf("template has %d fields, want %d", len(tmpl.Fields), len(fields))
	}
}

func TestDecodeNetFlowV9_DataWithoutTemplate(t *testing.T) {
	cache := NewNFV9TemplateCache()

	recData := buildNFV9RecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0,
		1, 2, 65000, 65001, 594000, 599000,
	)
	dataFS := buildNFV9DataFlowSet(256, recData)

	pkt := buildNFV9Packet(1, 600000, 1700000000, dataFS)

	flows, err := DecodeNetFlowV9(pkt, net.ParseIP("10.0.0.1"), cache)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No template cached → no flows decoded
	if len(flows) != 0 {
		t.Fatalf("expected 0 flows (no template), got %d", len(flows))
	}
}

func TestDecodeNetFlowV9_TooShortForHeader(t *testing.T) {
	data := make([]byte, 10)
	_, err := DecodeNetFlowV9(data, net.ParseIP("10.0.0.1"), NewNFV9TemplateCache())
	if err == nil {
		t.Fatal("expected error for short packet, got nil")
	}
}

func TestDecodeNetFlowV9_WrongVersion(t *testing.T) {
	pkt := buildNFV9Packet(1, 600000, 1700000000)
	binary.BigEndian.PutUint16(pkt[0:2], 5)
	_, err := DecodeNetFlowV9(pkt, net.ParseIP("10.0.0.1"), NewNFV9TemplateCache())
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
}

func TestDecodeNetFlowV9_TemplateCachePersists(t *testing.T) {
	cache := NewNFV9TemplateCache()
	exporterIP := net.ParseIP("10.0.0.1")

	fields := standardNFV9Fields()
	tmplFS := buildNFV9TemplateFlowSet(256, fields)

	// First packet: template only
	pkt1 := buildNFV9Packet(1, 600000, 1700000000, tmplFS)
	_, err := DecodeNetFlowV9(pkt1, exporterIP, cache)
	if err != nil {
		t.Fatalf("packet 1 error: %v", err)
	}

	// Second packet: data only (uses cached template)
	recData := buildNFV9RecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0,
		1, 2, 65000, 65001, 594000, 599000,
	)
	dataFS := buildNFV9DataFlowSet(256, recData)

	pkt2 := buildNFV9Packet(1, 600000, 1700000001, dataFS)
	flows, err := DecodeNetFlowV9(pkt2, exporterIP, cache)
	if err != nil {
		t.Fatalf("packet 2 error: %v", err)
	}

	if len(flows) != 1 {
		t.Fatalf("expected 1 flow from cached template, got %d", len(flows))
	}

	if !flows[0].SrcAddr.Equal(net.ParseIP("10.0.1.1")) {
		t.Errorf("SrcAddr = %s, want 10.0.1.1", flows[0].SrcAddr)
	}
}

func TestReadUintN(t *testing.T) {
	tests := []struct {
		data []byte
		want uint64
	}{
		{[]byte{42}, 42},
		{[]byte{0x00, 0x50}, 80},
		{[]byte{0x00, 0x00, 0x3A, 0x98}, 15000},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x98}, 15000},
	}
	for _, tt := range tests {
		got := readUintN(tt.data)
		if got != tt.want {
			t.Errorf("readUintN(%v) = %d, want %d", tt.data, got, tt.want)
		}
	}
}
