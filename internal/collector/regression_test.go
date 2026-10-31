package collector

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/darkace1998/FlowLens/internal/config"
)

// buildSFlowSampleHeaderOnly builds a sample envelope (type+len) whose body is
// only the standard sample header, with numRecords set to the given value and
// no records following.
func buildSFlowSampleHeaderOnly(format uint32, numRecords uint32) []byte {
	var hdrLen int
	var numRecordsOff int
	switch format {
	case sflowSampleTypeFlow:
		hdrLen = sflowFlowSampleHeaderLen
		numRecordsOff = 28
	case sflowSampleTypeCounter:
		hdrLen = sflowCounterSampleHeaderLen
		numRecordsOff = 8
	default:
		panic("unsupported format in test helper")
	}

	sample := make([]byte, 8+hdrLen)
	binary.BigEndian.PutUint32(sample[0:4], format) // enterprise=0, format=format
	binary.BigEndian.PutUint32(sample[4:8], uint32(hdrLen))
	binary.BigEndian.PutUint32(sample[8+numRecordsOff:8+numRecordsOff+4], numRecords)
	return sample
}

// Regression: a tiny datagram with numRecords=0xFFFFFFFF must not cause a huge
// preallocation (remote DoS via "fatal error: runtime: out of memory").
func TestDecodeSFlow_HugeNumRecordsNoOOM(t *testing.T) {
	agent := net.ParseIP("10.0.0.1")

	flowSample := buildSFlowSampleHeaderOnly(sflowSampleTypeFlow, 0xFFFFFFFF)
	counterSample := buildSFlowSampleHeaderOnly(sflowSampleTypeCounter, 0xFFFFFFFF)

	pkt := buildSFlowDatagram(agent, flowSample, counterSample)
	if len(pkt) > 128 {
		t.Fatalf("test datagram should be tiny, got %d bytes", len(pkt))
	}

	flows, counters, err := DecodeSFlow(pkt, agent)
	if err != nil {
		t.Fatalf("DecodeSFlow returned error: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("expected 0 flows, got %d", len(flows))
	}
	if len(counters) != 0 {
		t.Errorf("expected 0 counter samples, got %d", len(counters))
	}
}

// buildEtherVLANStackIPv4UDP builds an Ethernet frame with two stacked VLAN
// tags (802.1ad outer + 802.1Q inner) around an IPv4/UDP packet.
func buildEtherVLANStackIPv4UDP(srcIP, dstIP net.IP, outerVID, innerVID uint16, srcPort, dstPort uint16) []byte {
	base := buildEtherIPv4UDP(srcIP, dstIP, srcPort, dstPort) // eth + ip + udp

	pkt := make([]byte, 0, len(base)+8)
	pkt = append(pkt, base[:12]...)                          // dst+src MAC
	pkt = append(pkt, 0x88, 0xA8, byte(outerVID>>8), byte(outerVID)) // 802.1ad outer tag
	pkt = append(pkt, 0x81, 0x00, byte(innerVID>>8), byte(innerVID)) // 802.1Q inner tag
	pkt = append(pkt, 0x08, 0x00)                             // inner EtherType: IPv4
	pkt = append(pkt, base[14:]...)                           // IPv4+UDP payload
	return pkt
}

// Regression: stacked 802.1Q/802.1ad tags must be unwrapped to reach the
// inner EtherType, and the innermost VLAN ID must be reported.
func TestDecodeSFlow_StackedVLANTags(t *testing.T) {
	agent := net.ParseIP("10.0.0.1")
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("8.8.8.8")

	frame := buildEtherVLANStackIPv4UDP(srcIP, dstIP, 100, 200, 5353, 53)
	sample := buildSFlowFlowSample(1, 1, 2, frame)
	pkt := buildSFlowDatagram(agent, sample)

	flows, _, err := DecodeSFlow(pkt, agent)
	if err != nil {
		t.Fatalf("DecodeSFlow returned error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.VLAN != 200 {
		t.Errorf("expected inner VLAN 200, got %d", f.VLAN)
	}
	if f.EtherType != etherTypeIPv4 {
		t.Errorf("expected EtherType 0x%04x, got 0x%04x", etherTypeIPv4, f.EtherType)
	}
	if f.SrcPort != 5353 || f.DstPort != 53 {
		t.Errorf("expected ports 5353->53, got %d->%d", f.SrcPort, f.DstPort)
	}
	if !f.SrcAddr.Equal(srcIP) || !f.DstAddr.Equal(dstIP) {
		t.Errorf("unexpected addresses: %s -> %s", f.SrcAddr, f.DstAddr)
	}
}

type ipv6Ext struct {
	proto uint8 // this header's own next-header value (IPv6 protocol number)
	hdr   []byte
}

// buildEtherIPv6ExtChain builds Ethernet + IPv6 + ext header chain + UDP.
func buildEtherIPv6ExtChain(srcIP, dstIP net.IP, hopLimit uint8, exts []ipv6Ext, l4Proto uint8, srcPort, dstPort uint16) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], 8)

	payload := append([]byte{}, udp...)
	for i := len(exts) - 1; i >= 0; i-- {
		payload = append(append([]byte{}, exts[i].hdr...), payload...)
	}

	ip6 := make([]byte, ipv6HeaderSize)
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(len(payload)))
	if len(exts) > 0 {
		ip6[6] = exts[0].proto
	} else {
		ip6[6] = l4Proto
	}
	ip6[7] = hopLimit
	copy(ip6[8:24], srcIP.To16())
	copy(ip6[24:40], dstIP.To16())

	eth := make([]byte, ethHeaderSize)
	binary.BigEndian.PutUint16(eth[12:14], etherTypeIPv6)

	return append(append(eth, ip6...), payload...)
}

// Regression: IPv6 extension headers must be walked to find the real L4
// protocol/ports, and TTL must come from the hop limit.
func TestDecodeSFlow_IPv6ExtensionHeadersAndTTL(t *testing.T) {
	agent := net.ParseIP("10.0.0.1")
	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")

	// Hop-by-hop (type 0): next=dest-opts, hdrExtLen=0 → 8 bytes.
	bhh := make([]byte, 8)
	bhh[0] = protoIPv6DestOpts
	bhh[1] = 0

	// Dest-opts (type 60): next=UDP, hdrExtLen=1 → 16 bytes.
	dopts := make([]byte, 16)
	dopts[0] = protoUDP
	dopts[1] = 1

	frame := buildEtherIPv6ExtChain(srcIP, dstIP, 42,
		[]ipv6Ext{{proto: protoIPv6HopByHop, hdr: bhh}, {proto: protoIPv6DestOpts, hdr: dopts}},
		protoUDP, 5353, 53)
	sample := buildSFlowFlowSample(1, 1, 2, frame)
	pkt := buildSFlowDatagram(agent, sample)

	flows, _, err := DecodeSFlow(pkt, agent)
	if err != nil {
		t.Fatalf("DecodeSFlow returned error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.Protocol != protoUDP {
		t.Errorf("expected protocol UDP(17) after ext headers, got %d", f.Protocol)
	}
	if f.SrcPort != 5353 || f.DstPort != 53 {
		t.Errorf("expected ports 5353->53, got %d->%d", f.SrcPort, f.DstPort)
	}
	if f.TTL != 42 {
		t.Errorf("expected TTL 42 from hop limit, got %d", f.TTL)
	}
	if !f.SrcAddr.Equal(srcIP) || !f.DstAddr.Equal(dstIP) {
		t.Errorf("unexpected addresses: %s -> %s", f.SrcAddr, f.DstAddr)
	}
}

// Regression: v9 field 58 is the VLAN field, field 213 is isMulticast.
func TestDecodeNetFlowV9_VLANAndMulticastMapping(t *testing.T) {
	cache := NewNFV9TemplateCache()
	exporter := net.ParseIP("10.0.0.1")

	fields := []nfv9TemplateField{
		{Type: nfv9FieldInVLAN, Length: 2},      // 58 — VLAN
		{Type: nfv9FieldIsMulticast, Length: 1}, // 213 — isMulticast
		{Type: nfv9FieldIPv4SrcAddr, Length: 4},
	}
	tmplSet := buildNFV9TemplateFlowSet(256, fields)

	record := make([]byte, 7)
	binary.BigEndian.PutUint16(record[0:2], 512) // VLAN 512
	record[2] = 1                                 // isMulticast = true
	copy(record[3:7], net.ParseIP("10.1.1.1").To4())

	pkt := buildNFV9Packet(1, 1000, 1700000000, tmplSet, buildNFV9DataFlowSet(256, record))
	flows, err := DecodeNetFlowV9(pkt, exporter, cache)
	if err != nil {
		t.Fatalf("DecodeNetFlowV9 returned error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if flows[0].VLAN != 512 {
		t.Errorf("expected VLAN 512 from field 58, got %d", flows[0].VLAN)
	}
	if !flows[0].IsMulticast {
		t.Error("expected IsMulticast=true from field 213")
	}

	// Field 58 = 0 must NOT set IsMulticast anymore.
	record2 := make([]byte, 7)
	binary.BigEndian.PutUint16(record2[0:2], 0)
	record2[2] = 0
	copy(record2[3:7], net.ParseIP("10.1.1.2").To4())
	pkt2 := buildNFV9Packet(1, 1000, 1700000000, tmplSet, buildNFV9DataFlowSet(256, record2))
	flows2, err := DecodeNetFlowV9(pkt2, exporter, cache)
	if err != nil {
		t.Fatalf("DecodeNetFlowV9 returned error: %v", err)
	}
	if len(flows2) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows2))
	}
	if flows2[0].IsMulticast {
		t.Error("field 58 must not set IsMulticast")
	}
	if flows2[0].VLAN != 0 {
		t.Errorf("expected VLAN 0, got %d", flows2[0].VLAN)
	}
}

// Regression: template IDs < 256 are reserved and must not be cached.
func TestParseNFV9Templates_SkipsReservedIDs(t *testing.T) {
	cache := NewNFV9TemplateCache()

	reserved := buildNFV9TemplateFlowSet(100, standardNFV9Fields()) // templateID 100 < 256
	parseNFV9Templates(reserved[4:], 1, cache)
	if got := cache.get(1, 100); got != nil {
		t.Error("templateID 100 (<256) must not be cached")
	}

	valid := buildNFV9TemplateFlowSet(256, standardNFV9Fields())
	parseNFV9Templates(valid[4:], 1, cache)
	if got := cache.get(1, 256); got == nil {
		t.Error("templateID 256 should be cached")
	}
}

// Regression: variable-length template fields (Length == 65535) must be
// decoded with 1- or 3-byte length prefixes, and truncated trailing records
// must be dropped without looping forever.
func TestDecodeNetFlowV9_VariableLengthFields(t *testing.T) {
	cache := NewNFV9TemplateCache()
	exporter := net.ParseIP("10.0.0.1")

	fields := []nfv9TemplateField{
		{Type: nfv9FieldL4SrcPort, Length: 2},
		{Type: nfv9FieldIPv4SrcAddr, Length: 65535}, // variable-length
		{Type: nfv9FieldL4DstPort, Length: 2},
	}
	tmplSet := buildNFV9TemplateFlowSet(256, fields)

	// Record 1: srcPort=12345, 1-byte length prefix (4), srcAddr, dstPort=80.
	rec1 := make([]byte, 0, 9)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], 12345)
	rec1 = append(rec1, p[:]...)
	rec1 = append(rec1, 4)
	rec1 = append(rec1, net.ParseIP("10.2.2.2").To4()...)
	binary.BigEndian.PutUint16(p[:], 80)
	rec1 = append(rec1, p[:]...)

	// Record 2: srcPort=1, 3-byte length prefix (255 + 300), 300 value bytes, dstPort=2.
	rec2 := make([]byte, 0, 2+3+300+2)
	binary.BigEndian.PutUint16(p[:], 1)
	rec2 = append(rec2, p[:]...)
	rec2 = append(rec2, 255, 0x01, 0x2C) // 300
	rec2 = append(rec2, make([]byte, 300)...)
	binary.BigEndian.PutUint16(p[:], 2)
	rec2 = append(rec2, p[:]...)

	// Trailing partial record: srcPort=3 + 255 but the 2-byte length is truncated.
	partial := []byte{0x00, 0x03, 255, 0x00}

	data := append(append(rec1, rec2...), partial...)
	pkt := buildNFV9Packet(1, 1000, 1700000000, tmplSet, buildNFV9DataFlowSet(256, data))

	flows, err := DecodeNetFlowV9(pkt, exporter, cache)
	if err != nil {
		t.Fatalf("DecodeNetFlowV9 returned error: %v", err)
	}
	if len(flows) != 2 {
		t.Fatalf("expected 2 flows (partial trailing record dropped), got %d", len(flows))
	}
	if flows[0].SrcPort != 12345 || flows[0].DstPort != 80 {
		t.Errorf("record 1 ports: expected 12345->80, got %d->%d", flows[0].SrcPort, flows[0].DstPort)
	}
	if !flows[0].SrcAddr.Equal(net.ParseIP("10.2.2.2")) {
		t.Errorf("record 1 src addr: expected 10.2.2.2, got %s", flows[0].SrcAddr)
	}
	if flows[1].SrcPort != 1 || flows[1].DstPort != 2 {
		t.Errorf("record 2 ports: expected 1->2, got %d->%d", flows[1].SrcPort, flows[1].DstPort)
	}
}

// Regression: IPFIX template IDs < 256 are reserved and must not be cached.
func TestParseIPFIXTemplates_SkipsReservedIDs(t *testing.T) {
	cache := NewIPFIXTemplateCache()

	reserved := buildIPFIXTemplateSet(3, standardIPFIXFields()) // templateID 3 < 256
	parseIPFIXTemplates(reserved[4:], 1, cache)
	if got := cache.get(1, 3); got != nil {
		t.Error("templateID 3 (<256) must not be cached")
	}

	valid := buildIPFIXTemplateSet(256, standardIPFIXFields())
	parseIPFIXTemplates(valid[4:], 1, cache)
	if got := cache.get(1, 256); got == nil {
		t.Error("templateID 256 should be cached")
	}
}

// Regression: IPFIX variable-length fields (Length == 65535), including
// enterprise fields, must be decoded field-by-field with 1- or 3-byte
// length prefixes.
func TestDecodeIPFIX_VariableLengthFields(t *testing.T) {
	cache := NewIPFIXTemplateCache()
	exporter := net.ParseIP("10.0.0.1")

	fields := []ipfixTemplateField{
		{ID: ipfixFieldSourceTransPort, Length: 2},
		{ID: ipfixFieldSourceIPv4Addr, Length: 65535}, // variable-length
		{ID: 999, Length: 65535, IsEnterprise: true, EnterpriseNum: 1234}, // variable-length enterprise
		{ID: ipfixFieldDestTransPort, Length: 2},
	}
	tmplSet := buildIPFIXTemplateSet(256, fields)

	// Record: srcPort=8080, var srcAddr (1-byte len 4 + 4 bytes),
	// var enterprise field (3-byte header: 255 + len 300 + 300 bytes), dstPort=443.
	var p [2]byte
	rec := make([]byte, 0, 2+1+4+3+300+2)
	binary.BigEndian.PutUint16(p[:], 8080)
	rec = append(rec, p[:]...)
	rec = append(rec, 4)
	rec = append(rec, net.ParseIP("10.3.3.3").To4()...)
	rec = append(rec, 255, 0x01, 0x2C)
	rec = append(rec, make([]byte, 300)...)
	binary.BigEndian.PutUint16(p[:], 443)
	rec = append(rec, p[:]...)

	// Trailing partial record (truncated 2-byte length) must be dropped.
	rec = append(rec, 0x00, 0x01, 255, 0x00)

	pkt := buildIPFIXPacket(1, 1700000000, tmplSet, buildIPFIXDataSet(256, rec))
	flows, err := DecodeIPFIX(pkt, exporter, cache)
	if err != nil {
		t.Fatalf("DecodeIPFIX returned error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow (partial trailing record dropped), got %d", len(flows))
	}
	if flows[0].SrcPort != 8080 || flows[0].DstPort != 443 {
		t.Errorf("expected ports 8080->443, got %d->%d", flows[0].SrcPort, flows[0].DstPort)
	}
	if !flows[0].SrcAddr.Equal(net.ParseIP("10.3.3.3")) {
		t.Errorf("expected src addr 10.3.3.3, got %s", flows[0].SrcAddr)
	}
}

// Regression: buffer_size <= 0 must be clamped so reads don't always fail.
func TestNewCollector_ClampsBufferSize(t *testing.T) {
	if c := New(config.CollectorConfig{BufferSize: 0}, nil); c.cfg.BufferSize != 65535 {
		t.Errorf("BufferSize 0: expected clamp to 65535, got %d", c.cfg.BufferSize)
	}
	if c := New(config.CollectorConfig{BufferSize: -100}, nil); c.cfg.BufferSize != 65535 {
		t.Errorf("BufferSize -100: expected clamp to 65535, got %d", c.cfg.BufferSize)
	}
	if c := New(config.CollectorConfig{BufferSize: 4096}, nil); c.cfg.BufferSize != 4096 {
		t.Errorf("BufferSize 4096: expected 4096 unchanged, got %d", c.cfg.BufferSize)
	}
}
