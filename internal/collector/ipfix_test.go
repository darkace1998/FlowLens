package collector

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildIPFIXTemplateSet builds an IPFIX Template Set (ID 2).
func buildIPFIXTemplateSet(templateID uint16, fields []ipfixTemplateField) []byte {
	// Set header: 4 bytes
	// Template record header: 4 bytes (templateID, fieldCount)
	// Fields: 4 bytes each (+ 4 for enterprise)
	bodyLen := 4 // template record header
	for _, f := range fields {
		bodyLen += 4
		if f.IsEnterprise {
			bodyLen += 4
		}
	}
	totalLen := 4 + bodyLen
	data := make([]byte, totalLen)

	binary.BigEndian.PutUint16(data[0:2], 2)                // Set ID = Template
	binary.BigEndian.PutUint16(data[2:4], uint16(totalLen))  // Set Length

	binary.BigEndian.PutUint16(data[4:6], templateID)
	binary.BigEndian.PutUint16(data[6:8], uint16(len(fields)))

	off := 8
	for _, f := range fields {
		id := f.ID
		if f.IsEnterprise {
			id |= 0x8000
		}
		binary.BigEndian.PutUint16(data[off:off+2], id)
		binary.BigEndian.PutUint16(data[off+2:off+4], f.Length)
		off += 4

		if f.IsEnterprise {
			binary.BigEndian.PutUint32(data[off:off+4], f.EnterpriseNum)
			off += 4
		}
	}

	return data
}

// buildIPFIXDataSet builds an IPFIX Data Set with the given template ID.
func buildIPFIXDataSet(templateID uint16, recordData []byte) []byte {
	totalLen := 4 + len(recordData)
	data := make([]byte, totalLen)
	binary.BigEndian.PutUint16(data[0:2], templateID)
	binary.BigEndian.PutUint16(data[2:4], uint16(totalLen))
	copy(data[4:], recordData)
	return data
}

// buildIPFIXPacket assembles a complete IPFIX message from Sets.
func buildIPFIXPacket(obsDomainID uint32, exportTime uint32, sets ...[]byte) []byte {
	bodyLen := 0
	for _, s := range sets {
		bodyLen += len(s)
	}

	msgLen := ipfixHeaderSize + bodyLen
	pkt := make([]byte, msgLen)

	// Header
	binary.BigEndian.PutUint16(pkt[0:2], 10)              // version
	binary.BigEndian.PutUint16(pkt[2:4], uint16(msgLen))   // length
	binary.BigEndian.PutUint32(pkt[4:8], exportTime)
	binary.BigEndian.PutUint32(pkt[8:12], 1)               // sequence
	binary.BigEndian.PutUint32(pkt[12:16], obsDomainID)

	off := ipfixHeaderSize
	for _, s := range sets {
		copy(pkt[off:], s)
		off += len(s)
	}

	return pkt
}

// standardIPFIXFields returns a basic IPFIX template with common fields.
func standardIPFIXFields() []ipfixTemplateField {
	return []ipfixTemplateField{
		{ID: ipfixFieldSourceIPv4Addr, Length: 4},
		{ID: ipfixFieldDestIPv4Addr, Length: 4},
		{ID: ipfixFieldSourceTransPort, Length: 2},
		{ID: ipfixFieldDestTransPort, Length: 2},
		{ID: ipfixFieldProtocolID, Length: 1},
		{ID: ipfixFieldOctetDeltaCount, Length: 4},
		{ID: ipfixFieldPacketDeltaCount, Length: 4},
		{ID: ipfixFieldTCPControlBits, Length: 1},
		{ID: ipfixFieldIPClassOfService, Length: 1},
		{ID: ipfixFieldIngressInterface, Length: 2},
		{ID: ipfixFieldEgressInterface, Length: 2},
		{ID: ipfixFieldBgpSourceAS, Length: 4},
		{ID: ipfixFieldBgpDestAS, Length: 4},
	}
}

// buildIPFIXRecordData builds raw record data matching standardIPFIXFields.
func buildIPFIXRecordData(srcIP, dstIP net.IP, srcPort, dstPort uint16,
	proto uint8, octets, packets uint32, tcpFlags, tos uint8,
	ingressIf, egressIf uint16, srcAS, dstAS uint32) []byte {

	// Total: 4+4+2+2+1+4+4+1+1+2+2+4+4 = 35 bytes
	data := make([]byte, 35)
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
	binary.BigEndian.PutUint32(data[off:off+4], octets)
	off += 4
	binary.BigEndian.PutUint32(data[off:off+4], packets)
	off += 4
	data[off] = tcpFlags
	off++
	data[off] = tos
	off++
	binary.BigEndian.PutUint16(data[off:off+2], ingressIf)
	off += 2
	binary.BigEndian.PutUint16(data[off:off+2], egressIf)
	off += 2
	binary.BigEndian.PutUint32(data[off:off+4], srcAS)
	off += 4
	binary.BigEndian.PutUint32(data[off:off+4], dstAS)

	return data
}

func TestDecodeIPFIX_TemplateAndData(t *testing.T) {
	cache := NewIPFIXTemplateCache()
	exporterIP := net.ParseIP("172.16.0.1")

	fields := standardIPFIXFields()
	tmplSet := buildIPFIXTemplateSet(256, fields)

	recData := buildIPFIXRecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0,
		1, 2, 65000, 65001,
	)
	dataSet := buildIPFIXDataSet(256, recData)

	pkt := buildIPFIXPacket(1, 1700000000, tmplSet, dataSet)

	flows, err := DecodeIPFIX(pkt, exporterIP, cache)
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

	// Timestamp should be the export time
	expected := time.Unix(1700000000, 0)
	if !f.Timestamp.Equal(expected) {
		t.Errorf("Timestamp = %v, want %v", f.Timestamp, expected)
	}

	if !f.ExporterIP.Equal(exporterIP) {
		t.Errorf("ExporterIP = %s, want %s", f.ExporterIP, exporterIP)
	}
}

func TestDecodeIPFIX_MultipleRecords(t *testing.T) {
	cache := NewIPFIXTemplateCache()

	fields := standardIPFIXFields()
	tmplSet := buildIPFIXTemplateSet(256, fields)

	var allRecData []byte
	for i := 0; i < 3; i++ {
		rec := buildIPFIXRecordData(
			net.IPv4(10, 0, 1, byte(i+1)), net.IPv4(192, 168, 1, byte(i+1)),
			uint16(10000+i), 80, 6, uint32(1000*(i+1)), uint32(10*(i+1)),
			0x02, 0, 1, 2, 100, 200,
		)
		allRecData = append(allRecData, rec...)
	}
	dataSet := buildIPFIXDataSet(256, allRecData)

	pkt := buildIPFIXPacket(1, 1700000000, tmplSet, dataSet)

	flows, err := DecodeIPFIX(pkt, net.ParseIP("10.0.0.1"), cache)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(flows) != 3 {
		t.Fatalf("expected 3 flows, got %d", len(flows))
	}

	for i, f := range flows {
		wantOctet := byte(i + 1)
		srcBytes := f.SrcAddr.To4()
		if srcBytes == nil || srcBytes[3] != wantOctet {
			t.Errorf("flow[%d] SrcAddr last octet = %v, want %d", i, srcBytes, wantOctet)
		}
	}
}

func TestDecodeIPFIX_TemplateOnly(t *testing.T) {
	cache := NewIPFIXTemplateCache()

	fields := standardIPFIXFields()
	tmplSet := buildIPFIXTemplateSet(256, fields)

	pkt := buildIPFIXPacket(1, 1700000000, tmplSet)

	flows, err := DecodeIPFIX(pkt, net.ParseIP("10.0.0.1"), cache)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(flows) != 0 {
		t.Fatalf("expected 0 flows for template-only packet, got %d", len(flows))
	}

	tmpl := cache.get(1, 256)
	if tmpl == nil {
		t.Fatal("template was not cached")
	}
	if len(tmpl.Fields) != len(fields) {
		t.Errorf("template has %d fields, want %d", len(tmpl.Fields), len(fields))
	}
}

func TestDecodeIPFIX_DataWithoutTemplate(t *testing.T) {
	cache := NewIPFIXTemplateCache()

	recData := buildIPFIXRecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0,
		1, 2, 65000, 65001,
	)
	dataSet := buildIPFIXDataSet(256, recData)

	pkt := buildIPFIXPacket(1, 1700000000, dataSet)

	flows, err := DecodeIPFIX(pkt, net.ParseIP("10.0.0.1"), cache)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(flows) != 0 {
		t.Fatalf("expected 0 flows (no template), got %d", len(flows))
	}
}

func TestDecodeIPFIX_TooShortForHeader(t *testing.T) {
	data := make([]byte, 10)
	_, err := DecodeIPFIX(data, net.ParseIP("10.0.0.1"), NewIPFIXTemplateCache())
	if err == nil {
		t.Fatal("expected error for short packet, got nil")
	}
}

func TestDecodeIPFIX_WrongVersion(t *testing.T) {
	pkt := buildIPFIXPacket(1, 1700000000)
	binary.BigEndian.PutUint16(pkt[0:2], 9)
	_, err := DecodeIPFIX(pkt, net.ParseIP("10.0.0.1"), NewIPFIXTemplateCache())
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
}

func TestDecodeIPFIX_TemplateCachePersists(t *testing.T) {
	cache := NewIPFIXTemplateCache()
	exporterIP := net.ParseIP("10.0.0.1")

	fields := standardIPFIXFields()
	tmplSet := buildIPFIXTemplateSet(256, fields)

	// First packet: template only
	pkt1 := buildIPFIXPacket(1, 1700000000, tmplSet)
	_, err := DecodeIPFIX(pkt1, exporterIP, cache)
	if err != nil {
		t.Fatalf("packet 1 error: %v", err)
	}

	// Second packet: data only (uses cached template)
	recData := buildIPFIXRecordData(
		net.ParseIP("10.0.1.1"), net.ParseIP("192.168.1.1"),
		12345, 443, 6, 15000, 100, 0x12, 0,
		1, 2, 65000, 65001,
	)
	dataSet := buildIPFIXDataSet(256, recData)

	pkt2 := buildIPFIXPacket(1, 1700000001, dataSet)
	flows, err := DecodeIPFIX(pkt2, exporterIP, cache)
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

func TestDecodeIPFIX_EnterpriseField(t *testing.T) {
	cache := NewIPFIXTemplateCache()

	// Template with one standard field and one enterprise field
	fields := []ipfixTemplateField{
		{ID: ipfixFieldSourceIPv4Addr, Length: 4},
		{ID: ipfixFieldDestIPv4Addr, Length: 4},
		{ID: ipfixFieldProtocolID, Length: 1},
		{ID: 100, Length: 4, IsEnterprise: true, EnterpriseNum: 12345}, // custom enterprise field
	}
	tmplSet := buildIPFIXTemplateSet(256, fields)

	// Record data: srcIP(4) + dstIP(4) + proto(1) + enterpriseData(4) = 13 bytes
	recData := make([]byte, 13)
	copy(recData[0:4], net.ParseIP("10.0.1.1").To4())
	copy(recData[4:8], net.ParseIP("192.168.1.1").To4())
	recData[8] = 6 // TCP
	binary.BigEndian.PutUint32(recData[9:13], 42) // enterprise value (ignored)
	dataSet := buildIPFIXDataSet(256, recData)

	pkt := buildIPFIXPacket(1, 1700000000, tmplSet, dataSet)

	flows, err := DecodeIPFIX(pkt, net.ParseIP("10.0.0.1"), cache)
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
	if f.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6", f.Protocol)
	}
}
