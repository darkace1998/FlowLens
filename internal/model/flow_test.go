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
