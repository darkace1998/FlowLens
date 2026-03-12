package model

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestFlowString(t *testing.T) {
	f := Flow{
		Timestamp: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		SrcAddr:   net.ParseIP("10.0.1.50"),
		DstAddr:   net.ParseIP("192.168.1.1"),
		SrcPort:   12345,
		DstPort:   443,
		Protocol:  6,
		Bytes:     1024,
		Packets:   10,
	}

	s := f.String()
	if !strings.Contains(s, "10.0.1.50:12345") {
		t.Errorf("expected source address in output, got: %s", s)
	}
	if !strings.Contains(s, "192.168.1.1:443") {
		t.Errorf("expected destination address in output, got: %s", s)
	}
	if !strings.Contains(s, "TCP") {
		t.Errorf("expected TCP protocol name in output, got: %s", s)
	}
	if !strings.Contains(s, "1024 bytes") {
		t.Errorf("expected byte count in output, got: %s", s)
	}
	if !strings.Contains(s, "10 pkts") {
		t.Errorf("expected packet count in output, got: %s", s)
	}
}

func TestProtocolName(t *testing.T) {
	tests := []struct {
		proto uint8
		want  string
	}{
		{1, "ICMP"},
		{6, "TCP"},
		{17, "UDP"},
		{47, "GRE"},
		{50, "ESP"},
		{58, "ICMPv6"},
		{99, "Proto(99)"},
	}

	for _, tt := range tests {
		got := ProtocolName(tt.proto)
		if got != tt.want {
			t.Errorf("ProtocolName(%d) = %q, want %q", tt.proto, got, tt.want)
		}
	}
}

func TestAppProtocol(t *testing.T) {
	tests := []struct {
		proto   uint8
		srcPort uint16
		dstPort uint16
		want    string
	}{
		{6, 12345, 80, "HTTP"},
		{6, 12345, 443, "HTTPS"},
		{6, 12345, 22, "SSH"},
		{17, 12345, 53, "DNS"},
		{6, 12345, 25, "SMTP"},
		{6, 12345, 3389, "RDP"},
		{6, 12345, 3306, "MySQL"},
		{6, 12345, 5432, "PostgreSQL"},
		{17, 12345, 123, "NTP"},
		{6, 80, 12345, "HTTP"},   // reversed: src is well-known
		{1, 0, 0, "ICMP"},        // ICMP protocol
		{58, 0, 0, "ICMP"},       // ICMPv6
		{6, 50000, 60000, "Other"}, // unknown ports
	}

	for _, tt := range tests {
		got := AppProtocol(tt.proto, tt.srcPort, tt.dstPort)
		if got != tt.want {
			t.Errorf("AppProtocol(%d, %d, %d) = %q, want %q", tt.proto, tt.srcPort, tt.dstPort, got, tt.want)
		}
	}
}

func TestAppCategory(t *testing.T) {
	tests := []struct {
		appProto string
		want     string
	}{
		{"HTTP", "Web"},
		{"HTTPS", "Web"},
		{"DNS", "Network Services"},
		{"SSH", "Remote Access"},
		{"SMTP", "Email"},
		{"MySQL", "Database"},
		{"FTP", "File Transfer"},
		{"Other", "Other"},
	}

	for _, tt := range tests {
		got := AppCategory(tt.appProto)
		if got != tt.want {
			t.Errorf("AppCategory(%q) = %q, want %q", tt.appProto, got, tt.want)
		}
	}
}

func TestASName(t *testing.T) {
	tests := []struct {
		asn  uint32
		want string
	}{
		{15169, "Google"},
		{13335, "Cloudflare"},
		{16509, "Amazon (AWS)"},
		{0, "Private/Unknown"},
		{99999, "AS99999"},
	}

	for _, tt := range tests {
		got := ASName(tt.asn)
		if got != tt.want {
			t.Errorf("ASName(%d) = %q, want %q", tt.asn, got, tt.want)
		}
	}
}

func TestFlowClassify(t *testing.T) {
	tests := []struct {
		name     string
		proto    uint8
		srcPort  uint16
		dstPort  uint16
		wantApp  string
		wantCat  string
	}{
		{"HTTPS", 6, 12345, 443, "HTTPS", "Web"},
		{"HTTP", 6, 12345, 80, "HTTP", "Web"},
		{"DNS", 17, 12345, 53, "DNS", "Network Services"},
		{"SSH", 6, 12345, 22, "SSH", "Remote Access"},
		{"SMTP", 6, 12345, 25, "SMTP", "Email"},
		{"MySQL", 6, 12345, 3306, "MySQL", "Database"},
		{"Other", 6, 50000, 60000, "Other", "Other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Flow{
				Protocol: tt.proto,
				SrcPort:  tt.srcPort,
				DstPort:  tt.dstPort,
			}
			f.Classify()

			if f.AppProto != tt.wantApp {
				t.Errorf("Classify().AppProto = %q, want %q", f.AppProto, tt.wantApp)
			}
			if f.AppCat != tt.wantCat {
				t.Errorf("Classify().AppCat = %q, want %q", f.AppCat, tt.wantCat)
			}
		})
	}
}

func TestCalcThroughput(t *testing.T) {
	f := Flow{Bytes: 10000, Duration: 5 * time.Second}
	f.CalcThroughput()

	// 10000 bytes * 8 bits / 5 seconds = 16000 bps
	if f.ThroughputBPS != 16000 {
		t.Errorf("ThroughputBPS = %f, want 16000", f.ThroughputBPS)
	}

	// Zero duration should not panic.
	f2 := Flow{Bytes: 1000, Duration: 0}
	f2.CalcThroughput()
	if f2.ThroughputBPS != 0 {
		t.Errorf("ThroughputBPS with zero duration = %f, want 0", f2.ThroughputBPS)
	}

	// Large byte values should not overflow uint64 in the Bytes*8 computation.
	// 3 EB (3e18 bytes) * 8 = 24e18 which exceeds uint64 max (~18.4e18).
	// The result must still be a correct float64 value.
	f3 := Flow{Bytes: 3_000_000_000_000_000_000, Duration: 10 * time.Second}
	f3.CalcThroughput()
	expected := float64(3_000_000_000_000_000_000) * 8 / 10
	if f3.ThroughputBPS != expected {
		t.Errorf("ThroughputBPS for large bytes = %e, want %e", f3.ThroughputBPS, expected)
	}
}

func TestClassifySetsThruput(t *testing.T) {
	f := Flow{
		Protocol: 6,
		SrcPort:  12345,
		DstPort:  443,
		Bytes:    1000,
		Duration: 1 * time.Second,
	}
	f.Classify()
	if f.ThroughputBPS != 8000 {
		t.Errorf("Classify should set ThroughputBPS=8000, got %f", f.ThroughputBPS)
	}
}

func TestFlowKey(t *testing.T) {
	// FlowKey should be canonical regardless of direction.
	key1 := FlowKey(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 12345, 80, 6)
	key2 := FlowKey(net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 80, 12345, 6)

	if key1 != key2 {
		t.Errorf("FlowKey should be same regardless of direction: %q != %q", key1, key2)
	}

	// Different protocol should yield different key.
	key3 := FlowKey(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 12345, 80, 17)
	if key1 == key3 {
		t.Error("FlowKey should differ for different protocols")
	}
}

func TestStitchFlows(t *testing.T) {
	now := time.Now()

	flows := []Flow{
		// Client → Server
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("10.0.0.1"),
			DstAddr:   net.ParseIP("10.0.0.2"),
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  6,
			Bytes:     5000,
			Duration:  2 * time.Second,
		},
		// Server → Client (reverse 5-tuple, 500µs later)
		{
			Timestamp: now.Add(500 * time.Microsecond),
			SrcAddr:   net.ParseIP("10.0.0.2"),
			DstAddr:   net.ParseIP("10.0.0.1"),
			SrcPort:   80,
			DstPort:   12345,
			Protocol:  6,
			Bytes:     10000,
			Duration:  2 * time.Second,
		},
	}

	StitchFlows(flows)

	// Both flows should have throughput computed.
	if flows[0].ThroughputBPS <= 0 {
		t.Error("flows[0] should have ThroughputBPS > 0 after stitching")
	}
	if flows[1].ThroughputBPS <= 0 {
		t.Error("flows[1] should have ThroughputBPS > 0 after stitching")
	}

	// At least one should have RTT set from timestamp correlation.
	if flows[0].RTTMicros == 0 && flows[1].RTTMicros == 0 {
		t.Error("at least one flow should have RTTMicros > 0 after stitching")
	}

	// RTT should be ~500 microseconds.
	rtt := flows[1].RTTMicros
	if rtt != 500 {
		t.Errorf("RTTMicros = %d, want 500", rtt)
	}
}

func TestStitchFlows_SameDirectionNoRTT(t *testing.T) {
	now := time.Now()

	// Two flows in the SAME direction should NOT produce an RTT estimate.
	flows := []Flow{
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("10.0.0.1"),
			DstAddr:   net.ParseIP("10.0.0.2"),
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  6,
			Bytes:     5000,
			Duration:  2 * time.Second,
		},
		{
			Timestamp: now.Add(100 * time.Millisecond),
			SrcAddr:   net.ParseIP("10.0.0.1"),
			DstAddr:   net.ParseIP("10.0.0.2"),
			SrcPort:   12345,
			DstPort:   80,
			Protocol:  6,
			Bytes:     3000,
			Duration:  1 * time.Second,
		},
	}

	StitchFlows(flows)

	if flows[0].RTTMicros != 0 {
		t.Errorf("same-direction flows[0].RTTMicros = %d, want 0", flows[0].RTTMicros)
	}
	if flows[1].RTTMicros != 0 {
		t.Errorf("same-direction flows[1].RTTMicros = %d, want 0", flows[1].RTTMicros)
	}
}

func TestDetectRetransmissions(t *testing.T) {
	now := time.Now()

	flows := []Flow{
		// SYN: seq=1000, flags=SYN(0x02), payload=0 → consumes seq 1000-1001
		{
			Timestamp: now,
			SrcAddr:   net.ParseIP("10.0.0.1"), DstAddr: net.ParseIP("10.0.0.2"),
			SrcPort: 12345, DstPort: 80, Protocol: 6,
			Bytes: 40, Packets: 1, TCPFlags: 0x02, TCPSeqNum: 1000,
		},
		// Data: seq=1001, payload=100 bytes → covers seq 1001-1101
		{
			Timestamp: now.Add(1 * time.Millisecond),
			SrcAddr:   net.ParseIP("10.0.0.1"), DstAddr: net.ParseIP("10.0.0.2"),
			SrcPort: 12345, DstPort: 80, Protocol: 6,
			Bytes: 140, Packets: 1, TCPFlags: 0x10, TCPSeqNum: 1001,
		},
		// Retransmission: seq=1001 again (below maxSeqEnd=1101)
		{
			Timestamp: now.Add(50 * time.Millisecond),
			SrcAddr:   net.ParseIP("10.0.0.1"), DstAddr: net.ParseIP("10.0.0.2"),
			SrcPort: 12345, DstPort: 80, Protocol: 6,
			Bytes: 140, Packets: 1, TCPFlags: 0x10, TCPSeqNum: 1001,
		},
		// New data: seq=1101, payload=200 → covers seq 1101-1301 (not retransmission)
		{
			Timestamp: now.Add(100 * time.Millisecond),
			SrcAddr:   net.ParseIP("10.0.0.1"), DstAddr: net.ParseIP("10.0.0.2"),
			SrcPort: 12345, DstPort: 80, Protocol: 6,
			Bytes: 240, Packets: 1, TCPFlags: 0x10, TCPSeqNum: 1101,
		},
		// Reverse direction (different connKey, should not be flagged)
		{
			Timestamp: now.Add(2 * time.Millisecond),
			SrcAddr:   net.ParseIP("10.0.0.2"), DstAddr: net.ParseIP("10.0.0.1"),
			SrcPort: 80, DstPort: 12345, Protocol: 6,
			Bytes: 40, Packets: 1, TCPFlags: 0x12, TCPSeqNum: 5000,
		},
	}

	DetectRetransmissions(flows)

	if flows[0].Retransmissions != 0 {
		t.Error("SYN packet should not be flagged as retransmission")
	}
	if flows[1].Retransmissions != 0 {
		t.Error("first data packet should not be flagged as retransmission")
	}
	if flows[2].Retransmissions != 1 {
		t.Error("duplicate seq=1001 should be flagged as retransmission")
	}
	if flows[3].Retransmissions != 0 {
		t.Error("new data (seq=1101) should not be flagged as retransmission")
	}
	if flows[4].Retransmissions != 0 {
		t.Error("reverse direction packet should not be flagged as retransmission")
	}
}

func TestRetransmissionRate(t *testing.T) {
	f := Flow{Packets: 1000, Retransmissions: 50}
	rate := f.RetransmissionRate()
	if rate != 5.0 {
		t.Errorf("RetransmissionRate = %f, want 5.0", rate)
	}

	// Zero packets should return 0.
	f2 := Flow{Packets: 0, Retransmissions: 10}
	if f2.RetransmissionRate() != 0 {
		t.Error("RetransmissionRate with zero packets should be 0")
	}

	// Zero retransmissions should return 0.
	f3 := Flow{Packets: 1000, Retransmissions: 0}
	if f3.RetransmissionRate() != 0 {
		t.Error("RetransmissionRate with zero retransmissions should be 0")
	}
}

func TestPacketLossRate(t *testing.T) {
	f := Flow{Packets: 950, PacketLoss: 50}
	rate := f.PacketLossRate()
	// 50 / (950 + 50) * 100 = 5.0
	if rate != 5.0 {
		t.Errorf("PacketLossRate = %f, want 5.0", rate)
	}

	// Zero loss should return 0.
	f2 := Flow{Packets: 1000, PacketLoss: 0}
	if f2.PacketLossRate() != 0 {
		t.Error("PacketLossRate with zero loss should be 0")
	}
}

func TestIsVoIP(t *testing.T) {
	tests := []struct {
		name    string
		proto   uint8
		srcPort uint16
		dstPort uint16
		want    bool
	}{
		{"UDP RTP range dst", 17, 50000, 16000, true},
		{"UDP RTP range src", 17, 15000, 50000, true},
		{"UDP SIP 5060", 17, 50000, 5060, true},
		{"UDP SIP 5061", 17, 5061, 50000, true},
		{"UDP low ports", 17, 1234, 80, false},
		{"TCP RTP range", 6, 50000, 16000, false},     // TCP not VoIP
		{"UDP both high non-RTP", 17, 50000, 50001, false},
		// DNS should NOT be classified as VoIP even when ephemeral port is in RTP range.
		{"DNS query ephemeral in RTP", 17, 15000, 53, false},
		{"DNS response ephemeral in RTP", 17, 53, 15000, false},
		// Other well-known services below port 1024 should not be VoIP.
		{"NTP ephemeral in RTP", 17, 15000, 123, false},
		{"DHCP server", 17, 67, 15000, false},
		{"SNMP ephemeral in RTP", 17, 15000, 161, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Flow{Protocol: tt.proto, SrcPort: tt.srcPort, DstPort: tt.dstPort}
			if got := f.IsVoIP(); got != tt.want {
				t.Errorf("IsVoIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalcMOS(t *testing.T) {
	// Perfect conditions: should give high MOS (with 10ms codec delay, slight impairment).
	mos := CalcMOS(0, 0, 0)
	if mos < 4.3 {
		t.Errorf("CalcMOS(0,0,0) = %.2f, want >= 4.3", mos)
	}

	// Some jitter and RTT: MOS should decrease.
	mos2 := CalcMOS(30000, 100000, 0) // 30ms jitter, 100ms RTT
	if mos2 >= mos {
		t.Errorf("MOS with jitter/RTT (%.2f) should be less than near-perfect (%.2f)", mos2, mos)
	}

	// High loss: MOS should drop significantly.
	mos3 := CalcMOS(0, 0, 10) // 10% loss
	if mos3 >= mos {
		t.Errorf("CalcMOS with 10%% loss = %.2f, should be less than no-loss (%.2f)", mos3, mos)
	}

	// Extreme conditions: MOS should not go below 1.0.
	mos4 := CalcMOS(1000000, 5000000, 50) // massive jitter, RTT, loss
	if mos4 < 1.0 {
		t.Errorf("CalcMOS with extreme values = %.2f, should not go below 1.0", mos4)
	}
}

func TestClassifySetsMOSForVoIP(t *testing.T) {
	f := Flow{
		Protocol:     17,        // UDP
		SrcPort:      50000,
		DstPort:      16000,     // RTP range
		JitterMicros: 10000,     // 10ms
		RTTMicros:    50000,     // 50ms
		Packets:      950,
		PacketLoss:   50,
	}
	f.Classify()

	if f.MOS == 0 {
		t.Error("Classify should compute MOS for VoIP flows")
	}
	if f.MOS < 1.0 || f.MOS > 4.41 {
		t.Errorf("MOS = %.2f, should be in range [1.0, 4.41]", f.MOS)
	}
}

func TestSIPDetection(t *testing.T) {
	if got := AppProtocol(17, 50000, 5060); got != "SIP" {
		t.Errorf("AppProtocol(17, 50000, 5060) = %q, want SIP", got)
	}
	if got := AppCategory("SIP"); got != "Multimedia" {
		t.Errorf("AppCategory(SIP) = %q, want Multimedia", got)
	}
}

func TestInterfaceName(t *testing.T) {
	names := map[string]string{
		"1": "eth0",
		"2": "GigabitEthernet0/1",
	}

	tests := []struct {
		ifIndex uint32
		names   map[string]string
		want    string
	}{
		{1, names, "eth0"},
		{2, names, "GigabitEthernet0/1"},
		{3, names, "if3"},
		{0, names, "—"},
		{1, nil, "if1"},
		{0, nil, "—"},
		{99, map[string]string{}, "if99"},
	}

	for _, tt := range tests {
		got := InterfaceName(tt.ifIndex, tt.names)
		if got != tt.want {
			t.Errorf("InterfaceName(%d, ...) = %q, want %q", tt.ifIndex, got, tt.want)
		}
	}
}

func TestFormatMAC(t *testing.T) {
	tests := []struct {
		mac  net.HardwareAddr
		want string
	}{
		{nil, "—"},
		{net.HardwareAddr{}, "—"},
		{net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "aa:bb:cc:dd:ee:ff"},
		{net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "00:00:00:00:00:00"},
	}
	for _, tt := range tests {
		got := FormatMAC(tt.mac)
		if got != tt.want {
			t.Errorf("FormatMAC(%v) = %q, want %q", tt.mac, got, tt.want)
		}
	}
}

func TestFormatEtherType(t *testing.T) {
	tests := []struct {
		et   uint16
		want string
	}{
		{0x0800, "IPv4"},
		{0x86DD, "IPv6"},
		{0x0806, "ARP"},
		{0x8100, "802.1Q"},
		{0, "—"},
		{0x1234, "0x1234"},
	}
	for _, tt := range tests {
		got := FormatEtherType(tt.et)
		if got != tt.want {
			t.Errorf("FormatEtherType(0x%04X) = %q, want %q", tt.et, got, tt.want)
		}
	}
}

func TestFormatTCPFlags(t *testing.T) {
	tests := []struct {
		flags uint8
		want  string
	}{
		{0x00, "—"},         // no flags
		{0x02, "SYN"},       // SYN only
		{0x12, "SYN ACK"},   // SYN+ACK
		{0x10, "ACK"},       // ACK only
		{0x11, "FIN ACK"},   // FIN+ACK
		{0x18, "PSH ACK"},   // PSH+ACK
		{0x04, "RST"},       // RST only
		{0x14, "RST ACK"},   // RST+ACK
		{0x01, "FIN"},       // FIN only
		{0x3F, "FIN SYN RST PSH ACK URG"}, // all lower 6 flags
		{0xFF, "FIN SYN RST PSH ACK URG ECE CWR"}, // all 8 flags
		{0x40, "ECE"},       // ECE only
		{0x80, "CWR"},       // CWR only
		{0xC0, "ECE CWR"},   // ECE+CWR
	}
	for _, tt := range tests {
		got := FormatTCPFlags(tt.flags)
		if got != tt.want {
			t.Errorf("FormatTCPFlags(0x%02x) = %q, want %q", tt.flags, got, tt.want)
		}
	}
}
