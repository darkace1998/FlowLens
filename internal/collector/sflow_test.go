package collector

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildSFlowDatagram constructs a minimal sFlow v5 datagram with the given samples.
// samples is a slice of pre-built sample blobs (each includes type+len+data).
func buildSFlowDatagram(agentIP net.IP, samples ...[]byte) []byte {
	// Header: version(4) + addrType(4) + agentAddr(4) + subAgentID(4) + seqNo(4) + uptime(4) + numSamples(4) = 28
	pkt := make([]byte, 28)
	binary.BigEndian.PutUint32(pkt[0:4], 5) // version
	binary.BigEndian.PutUint32(pkt[4:8], 1) // addrType=IPv4

	ip4 := agentIP.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	copy(pkt[8:12], ip4)

	binary.BigEndian.PutUint32(pkt[12:16], 0)          // subAgentID
	binary.BigEndian.PutUint32(pkt[16:20], 1)           // seqNumber
	binary.BigEndian.PutUint32(pkt[20:24], 600000)      // sysUptime (600s)
	binary.BigEndian.PutUint32(pkt[24:28], uint32(len(samples))) // numSamples

	for _, s := range samples {
		pkt = append(pkt, s...)
	}

	return pkt
}

// buildSFlowFlowSample constructs a standard sFlow flow sample with one raw packet header record.
func buildSFlowFlowSample(samplingRate, inputIface, outputIface uint32, rawPktHeader []byte) []byte {
	// Flow sample header: seqNo(4)+srcIDTypeIndex(4)+samplingRate(4)+samplePool(4)+drops(4)+
	//                     input(4)+output(4)+numRecords(4) = 32
	// Raw packet header record: recordType(4)+recordLen(4)+headerProtocol(4)+frameLength(4)+
	//                           strippedBytes(4)+headerLength(4)+header(var)

	recordDataLen := 16 + len(rawPktHeader)
	// Pad to 4-byte boundary
	pad := (4 - (len(rawPktHeader) % 4)) % 4
	recordDataLenPadded := recordDataLen + pad

	sampleDataLen := 32 + 8 + recordDataLenPadded

	// Sample envelope: type(4) + length(4)
	sample := make([]byte, 8+sampleDataLen)

	// Sample type: enterprise=0, format=1 (flow sample)
	binary.BigEndian.PutUint32(sample[0:4], 1) // (0 << 12) | 1
	binary.BigEndian.PutUint32(sample[4:8], uint32(sampleDataLen))

	off := 8
	// seqNo
	binary.BigEndian.PutUint32(sample[off:off+4], 1)
	off += 4
	// sourceIDTypeIndex (type=0, index=1)
	binary.BigEndian.PutUint32(sample[off:off+4], 1)
	off += 4
	// samplingRate
	binary.BigEndian.PutUint32(sample[off:off+4], samplingRate)
	off += 4
	// samplePool
	binary.BigEndian.PutUint32(sample[off:off+4], 100)
	off += 4
	// drops
	binary.BigEndian.PutUint32(sample[off:off+4], 0)
	off += 4
	// input (format=0 in top 2 bits, value in bottom 30)
	binary.BigEndian.PutUint32(sample[off:off+4], inputIface)
	off += 4
	// output
	binary.BigEndian.PutUint32(sample[off:off+4], outputIface)
	off += 4
	// numRecords
	binary.BigEndian.PutUint32(sample[off:off+4], 1)
	off += 4

	// Record type: enterprise=0, format=1 (raw packet header)
	binary.BigEndian.PutUint32(sample[off:off+4], 1) // (0 << 12) | 1
	off += 4
	// Record length
	binary.BigEndian.PutUint32(sample[off:off+4], uint32(recordDataLen))
	off += 4

	// headerProtocol = 1 (Ethernet)
	binary.BigEndian.PutUint32(sample[off:off+4], 1)
	off += 4
	// frameLength
	binary.BigEndian.PutUint32(sample[off:off+4], uint32(len(rawPktHeader)))
	off += 4
	// strippedBytes
	binary.BigEndian.PutUint32(sample[off:off+4], 0)
	off += 4
	// headerLength
	binary.BigEndian.PutUint32(sample[off:off+4], uint32(len(rawPktHeader)))
	off += 4
	// header data
	copy(sample[off:], rawPktHeader)

	return sample
}

// buildSFlowCounterSample constructs a standard sFlow counter sample with one generic interface counter record.
func buildSFlowCounterSample(ifIndex uint32, ifSpeed uint64, inOctets, outOctets uint64, inPkts, outPkts uint32) []byte {
	// Counter sample header: seqNo(4)+sourceIDTypeIndex(4)+numRecords(4) = 12
	// Generic interface counters record: 88 bytes
	recordLen := 88
	sampleDataLen := 12 + 8 + recordLen

	sample := make([]byte, 8+sampleDataLen)

	// Sample type: enterprise=0, format=2 (counter sample)
	binary.BigEndian.PutUint32(sample[0:4], 2) // (0 << 12) | 2
	binary.BigEndian.PutUint32(sample[4:8], uint32(sampleDataLen))

	off := 8
	// seqNo
	binary.BigEndian.PutUint32(sample[off:off+4], 1)
	off += 4
	// sourceIDTypeIndex
	binary.BigEndian.PutUint32(sample[off:off+4], 1)
	off += 4
	// numRecords
	binary.BigEndian.PutUint32(sample[off:off+4], 1)
	off += 4

	// Record type: enterprise=0, format=1 (generic interface counters)
	binary.BigEndian.PutUint32(sample[off:off+4], 1) // (0 << 12) | 1
	off += 4
	// Record length
	binary.BigEndian.PutUint32(sample[off:off+4], uint32(recordLen))
	off += 4

	rec := sample[off : off+recordLen]
	binary.BigEndian.PutUint32(rec[0:4], ifIndex)
	binary.BigEndian.PutUint32(rec[4:8], 6) // ifType=ethernet
	binary.BigEndian.PutUint64(rec[8:16], ifSpeed)
	binary.BigEndian.PutUint32(rec[16:20], 1)  // ifDirection=full-duplex
	binary.BigEndian.PutUint32(rec[20:24], 3)  // ifStatus=admin+oper up
	binary.BigEndian.PutUint64(rec[24:32], inOctets)
	binary.BigEndian.PutUint32(rec[32:36], inPkts)  // inUcastPkts
	binary.BigEndian.PutUint32(rec[36:40], 0)       // inMulticastPkts
	binary.BigEndian.PutUint32(rec[40:44], 0)       // inBroadcastPkts
	binary.BigEndian.PutUint32(rec[44:48], 0)       // inDiscards
	binary.BigEndian.PutUint32(rec[48:52], 0)       // inErrors
	binary.BigEndian.PutUint32(rec[52:56], 0)       // inUnknownProtos
	binary.BigEndian.PutUint64(rec[56:64], outOctets)
	binary.BigEndian.PutUint32(rec[64:68], outPkts) // outUcastPkts
	binary.BigEndian.PutUint32(rec[68:72], 0)       // outMulticastPkts
	binary.BigEndian.PutUint32(rec[72:76], 0)       // outBroadcastPkts
	binary.BigEndian.PutUint32(rec[76:80], 0)       // outDiscards
	binary.BigEndian.PutUint32(rec[80:84], 0)       // outErrors
	// 84:88 = pad to 88

	return sample
}

// buildEtherIPv4TCP constructs a minimal Ethernet+IPv4+TCP packet for sFlow testing.
func buildEtherIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 14+20+20) // eth + ip + tcp
	// Dst MAC
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// Src MAC
	copy(pkt[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	// EtherType: IPv4
	pkt[12] = 0x08
	pkt[13] = 0x00

	// IPv4 header
	ip := pkt[14:]
	ip[0] = 0x45 // Version 4, IHL 5
	ip[1] = 0    // ToS
	totalLen := 20 + 20
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// TCP header
	tcp := ip[20:]
	tcp[0] = byte(srcPort >> 8)
	tcp[1] = byte(srcPort)
	tcp[2] = byte(dstPort >> 8)
	tcp[3] = byte(dstPort)
	tcp[12] = 0x50 // Data offset: 5
	tcp[13] = 0x02 // SYN

	return pkt
}

// buildEtherIPv4UDP constructs a minimal Ethernet+IPv4+UDP packet for sFlow testing.
func buildEtherIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 14+20+8) // eth + ip + udp
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	pkt[12] = 0x08
	pkt[13] = 0x00

	ip := pkt[14:]
	ip[0] = 0x45
	totalLen := 20 + 8
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	udp := ip[20:]
	udp[0] = byte(srcPort >> 8)
	udp[1] = byte(srcPort)
	udp[2] = byte(dstPort >> 8)
	udp[3] = byte(dstPort)
	udpLen := 8
	udp[4] = byte(udpLen >> 8)
	udp[5] = byte(udpLen)

	return pkt
}

func TestDecodeSFlow_FlowSample_TCP(t *testing.T) {
	agentIP := net.ParseIP("10.0.0.1")
	exporterIP := net.ParseIP("172.16.0.1")

	rawPkt := buildEtherIPv4TCP(net.ParseIP("10.1.0.1"), net.ParseIP("10.2.0.1"), 12345, 443)
	sample := buildSFlowFlowSample(100, 3, 4, rawPkt)
	datagram := buildSFlowDatagram(agentIP, sample)

	flows, counters, err := DecodeSFlow(datagram, exporterIP)
	if err != nil {
		t.Fatalf("DecodeSFlow error: %v", err)
	}
	if len(counters) != 0 {
		t.Errorf("expected 0 counter samples, got %d", len(counters))
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	f := flows[0]
	if !f.SrcAddr.Equal(net.ParseIP("10.1.0.1").To4()) {
		t.Errorf("SrcAddr = %s, want 10.1.0.1", f.SrcAddr)
	}
	if !f.DstAddr.Equal(net.ParseIP("10.2.0.1").To4()) {
		t.Errorf("DstAddr = %s, want 10.2.0.1", f.DstAddr)
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
	if f.TCPFlags != 0x02 {
		t.Errorf("TCPFlags = 0x%02x, want 0x02 (SYN)", f.TCPFlags)
	}
	if f.InputIface != 3 {
		t.Errorf("InputIface = %d, want 3", f.InputIface)
	}
	if f.OutputIface != 4 {
		t.Errorf("OutputIface = %d, want 4", f.OutputIface)
	}
	if !f.ExporterIP.Equal(exporterIP) {
		t.Errorf("ExporterIP = %s, want %s", f.ExporterIP, exporterIP)
	}
	// With sampling rate 100 and frame length = len(rawPkt), bytes should be multiplied.
	expectedBytes := uint64(len(rawPkt)) * 100
	if f.Bytes != expectedBytes {
		t.Errorf("Bytes = %d, want %d (frame=%d * sampling=100)", f.Bytes, expectedBytes, len(rawPkt))
	}
	if f.Packets != 100 {
		t.Errorf("Packets = %d, want 100 (1 * sampling rate 100)", f.Packets)
	}
	if f.AppProto != "HTTPS" {
		t.Errorf("AppProto = %q, want HTTPS", f.AppProto)
	}
}

func TestDecodeSFlow_FlowSample_UDP(t *testing.T) {
	agentIP := net.ParseIP("10.0.0.1")
	exporterIP := net.ParseIP("172.16.0.1")

	rawPkt := buildEtherIPv4UDP(net.ParseIP("10.1.0.1"), net.ParseIP("8.8.8.8"), 54321, 53)
	sample := buildSFlowFlowSample(1, 1, 2, rawPkt)
	datagram := buildSFlowDatagram(agentIP, sample)

	flows, _, err := DecodeSFlow(datagram, exporterIP)
	if err != nil {
		t.Fatalf("DecodeSFlow error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	f := flows[0]
	if f.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17 (UDP)", f.Protocol)
	}
	if f.DstPort != 53 {
		t.Errorf("DstPort = %d, want 53", f.DstPort)
	}
	if f.AppProto != "DNS" {
		t.Errorf("AppProto = %q, want DNS", f.AppProto)
	}
}

func TestDecodeSFlow_CounterSample(t *testing.T) {
	agentIP := net.ParseIP("10.0.0.1")
	exporterIP := net.ParseIP("172.16.0.1")

	sample := buildSFlowCounterSample(5, 1000000000, 123456789, 987654321, 1000, 2000)
	datagram := buildSFlowDatagram(agentIP, sample)

	flows, counters, err := DecodeSFlow(datagram, exporterIP)
	if err != nil {
		t.Fatalf("DecodeSFlow error: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("expected 0 flows, got %d", len(flows))
	}
	if len(counters) != 1 {
		t.Fatalf("expected 1 counter sample, got %d", len(counters))
	}

	cs := counters[0]
	if cs.IfIndex != 5 {
		t.Errorf("IfIndex = %d, want 5", cs.IfIndex)
	}
	if cs.IfSpeed != 1000000000 {
		t.Errorf("IfSpeed = %d, want 1000000000", cs.IfSpeed)
	}
	if cs.InOctets != 123456789 {
		t.Errorf("InOctets = %d, want 123456789", cs.InOctets)
	}
	if cs.OutOctets != 987654321 {
		t.Errorf("OutOctets = %d, want 987654321", cs.OutOctets)
	}
	if cs.InPackets != 1000 {
		t.Errorf("InPackets = %d, want 1000", cs.InPackets)
	}
	if cs.OutPackets != 2000 {
		t.Errorf("OutPackets = %d, want 2000", cs.OutPackets)
	}
	if !cs.AgentIP.Equal(agentIP.To4()) {
		t.Errorf("AgentIP = %s, want %s", cs.AgentIP, agentIP)
	}
}

func TestDecodeSFlow_MixedSamples(t *testing.T) {
	agentIP := net.ParseIP("10.0.0.1")
	exporterIP := net.ParseIP("172.16.0.1")

	rawPkt := buildEtherIPv4TCP(net.ParseIP("10.1.0.1"), net.ParseIP("10.2.0.1"), 8080, 80)
	flowSample := buildSFlowFlowSample(10, 1, 2, rawPkt)
	counterSample := buildSFlowCounterSample(1, 10000000000, 500000, 300000, 5000, 3000)

	datagram := buildSFlowDatagram(agentIP, flowSample, counterSample)

	flows, counters, err := DecodeSFlow(datagram, exporterIP)
	if err != nil {
		t.Fatalf("DecodeSFlow error: %v", err)
	}
	if len(flows) != 1 {
		t.Errorf("expected 1 flow, got %d", len(flows))
	}
	if len(counters) != 1 {
		t.Errorf("expected 1 counter, got %d", len(counters))
	}
}

func TestDecodeSFlow_TooShort(t *testing.T) {
	_, _, err := DecodeSFlow([]byte{0, 0, 0, 5}, nil)
	if err == nil {
		t.Error("expected error for too-short packet")
	}
}

func TestDecodeSFlow_WrongVersion(t *testing.T) {
	pkt := buildSFlowDatagram(net.ParseIP("10.0.0.1"))
	// Set version to 4
	binary.BigEndian.PutUint32(pkt[0:4], 4)
	_, _, err := DecodeSFlow(pkt, nil)
	if err == nil {
		t.Error("expected error for wrong version")
	}
}

func TestDecodeSFlow_InvalidAgentAddrType(t *testing.T) {
	pkt := make([]byte, 28)
	binary.BigEndian.PutUint32(pkt[0:4], 5) // version
	binary.BigEndian.PutUint32(pkt[4:8], 3) // invalid addr type

	_, _, err := DecodeSFlow(pkt, nil)
	if err == nil {
		t.Error("expected error for invalid agent address type")
	}
}

func TestDecodeSFlow_SamplingRateMultiplier(t *testing.T) {
	agentIP := net.ParseIP("10.0.0.1")
	exporterIP := net.ParseIP("172.16.0.1")

	rawPkt := buildEtherIPv4TCP(net.ParseIP("10.1.0.1"), net.ParseIP("10.2.0.1"), 1234, 80)
	// Sampling rate = 500
	sample := buildSFlowFlowSample(500, 1, 2, rawPkt)
	datagram := buildSFlowDatagram(agentIP, sample)

	flows, _, err := DecodeSFlow(datagram, exporterIP)
	if err != nil {
		t.Fatalf("DecodeSFlow error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	f := flows[0]
	if f.Packets != 500 {
		t.Errorf("Packets = %d, want 500 (1 * 500)", f.Packets)
	}
	expectedBytes := uint64(len(rawPkt)) * 500
	if f.Bytes != expectedBytes {
		t.Errorf("Bytes = %d, want %d (frame=%d * 500)", f.Bytes, expectedBytes, len(rawPkt))
	}
}

func TestDecodeSFlow_NonEthernetProtocol(t *testing.T) {
	agentIP := net.ParseIP("10.0.0.1")
	exporterIP := net.ParseIP("172.16.0.1")

	// Build a flow sample with headerProtocol != 1 (not Ethernet)
	// Use a manually constructed sample
	rawPkt := make([]byte, 40) // dummy payload

	recordDataLen := 16 + len(rawPkt)
	sampleDataLen := 32 + 8 + recordDataLen

	sample := make([]byte, 8+sampleDataLen)
	binary.BigEndian.PutUint32(sample[0:4], 1) // flow sample
	binary.BigEndian.PutUint32(sample[4:8], uint32(sampleDataLen))

	off := 8
	binary.BigEndian.PutUint32(sample[off:off+4], 1)   // seqNo
	binary.BigEndian.PutUint32(sample[off+4:off+8], 1)  // srcID
	binary.BigEndian.PutUint32(sample[off+8:off+12], 1) // samplingRate
	binary.BigEndian.PutUint32(sample[off+12:off+16], 0) // samplePool
	binary.BigEndian.PutUint32(sample[off+16:off+20], 0) // drops
	binary.BigEndian.PutUint32(sample[off+20:off+24], 1) // input
	binary.BigEndian.PutUint32(sample[off+24:off+28], 2) // output
	binary.BigEndian.PutUint32(sample[off+28:off+32], 1) // numRecords
	off += 32

	// Record: raw packet header with protocol=2 (not Ethernet)
	binary.BigEndian.PutUint32(sample[off:off+4], 1) // record type
	binary.BigEndian.PutUint32(sample[off+4:off+8], uint32(recordDataLen))
	off += 8
	binary.BigEndian.PutUint32(sample[off:off+4], 2) // headerProtocol=2 (not Ethernet)
	binary.BigEndian.PutUint32(sample[off+4:off+8], 40) // frameLength
	binary.BigEndian.PutUint32(sample[off+8:off+12], 0) // strippedBytes
	binary.BigEndian.PutUint32(sample[off+12:off+16], 40) // headerLength
	copy(sample[off+16:], rawPkt)

	datagram := buildSFlowDatagram(agentIP, sample)

	flows, _, err := DecodeSFlow(datagram, exporterIP)
	if err != nil {
		t.Fatalf("DecodeSFlow error: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("expected 0 flows for non-Ethernet protocol, got %d", len(flows))
	}
}
