package capture

import (
	"net"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/model"
)

// buildTCPv4Packet constructs a minimal Ethernet+IPv4+TCP packet for testing.
func buildTCPv4Packet(srcIP, dstIP net.IP, srcPort, dstPort uint16, payloadLen int) []byte {
	// Ethernet header (14 bytes)
	pkt := make([]byte, 14+20+20+payloadLen) // eth + ip + tcp + payload
	// Dst MAC
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// Src MAC
	copy(pkt[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	// EtherType: IPv4
	pkt[12] = 0x08
	pkt[13] = 0x00

	// IPv4 header (20 bytes)
	ip := pkt[14:]
	ip[0] = 0x45 // Version 4, IHL 5
	ip[1] = 0    // ToS
	totalLen := 20 + 20 + payloadLen
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[8] = 64  // TTL
	ip[9] = 6   // Protocol: TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// TCP header (20 bytes)
	tcp := ip[20:]
	tcp[0] = byte(srcPort >> 8)
	tcp[1] = byte(srcPort)
	tcp[2] = byte(dstPort >> 8)
	tcp[3] = byte(dstPort)
	tcp[12] = 0x50 // Data offset: 5 (20 bytes)
	tcp[13] = 0x02 // SYN flag

	return pkt
}

// buildUDPv4Packet constructs a minimal Ethernet+IPv4+UDP packet for testing.
func buildUDPv4Packet(srcIP, dstIP net.IP, srcPort, dstPort uint16, payloadLen int) []byte {
	pkt := make([]byte, 14+20+8+payloadLen) // eth + ip + udp + payload
	// Dst MAC
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// Src MAC
	copy(pkt[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	// EtherType: IPv4
	pkt[12] = 0x08
	pkt[13] = 0x00

	// IPv4 header (20 bytes)
	ip := pkt[14:]
	ip[0] = 0x45
	ip[1] = 0
	totalLen := 20 + 8 + payloadLen
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[8] = 64
	ip[9] = 17 // Protocol: UDP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// UDP header (8 bytes)
	udp := ip[20:]
	udp[0] = byte(srcPort >> 8)
	udp[1] = byte(srcPort)
	udp[2] = byte(dstPort >> 8)
	udp[3] = byte(dstPort)
	udpLen := 8 + payloadLen
	udp[4] = byte(udpLen >> 8)
	udp[5] = byte(udpLen)

	return pkt
}

func TestDecodeEthernet_TCPv4(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("192.168.1.1")
	pkt := buildTCPv4Packet(srcIP, dstIP, 12345, 443, 100)

	now := time.Now()
	f, ok := decodeEthernet(pkt, now)
	if !ok {
		t.Fatal("decodeEthernet returned false for valid TCPv4 packet")
	}

	if !f.SrcAddr.Equal(srcIP.To4()) {
		t.Errorf("SrcAddr = %s, want %s", f.SrcAddr, srcIP)
	}
	if !f.DstAddr.Equal(dstIP.To4()) {
		t.Errorf("DstAddr = %s, want %s", f.DstAddr, dstIP)
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
	if f.Packets != 1 {
		t.Errorf("Packets = %d, want 1", f.Packets)
	}
	if f.AppProto != "HTTPS" {
		t.Errorf("AppProto = %q, want HTTPS", f.AppProto)
	}
}

func TestDecodeEthernet_UDPv4(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("8.8.8.8")
	pkt := buildUDPv4Packet(srcIP, dstIP, 54321, 53, 50)

	f, ok := decodeEthernet(pkt, time.Now())
	if !ok {
		t.Fatal("decodeEthernet returned false for valid UDPv4 packet")
	}

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

func TestDecodeEthernet_TooShort(t *testing.T) {
	_, ok := decodeEthernet([]byte{0x00, 0x01}, time.Now())
	if ok {
		t.Error("decodeEthernet should return false for too-short packet")
	}
}

func TestDecodeEthernet_NonIP(t *testing.T) {
	// ARP packet (EtherType 0x0806)
	pkt := make([]byte, 42)
	pkt[12] = 0x08
	pkt[13] = 0x06

	_, ok := decodeEthernet(pkt, time.Now())
	if ok {
		t.Error("decodeEthernet should return false for non-IP (ARP) packet")
	}
}

func TestDecodeEthernet_VLAN(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("10.0.0.2")

	// Build a VLAN-tagged packet manually.
	pkt := make([]byte, 18+20+20) // eth(14)+vlan(4)+ip(20)+tcp(20)
	// Dst/Src MAC
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	// 802.1Q tag
	pkt[12] = 0x81
	pkt[13] = 0x00
	pkt[14] = 0x00 // VLAN ID
	pkt[15] = 0x0A // VLAN ID = 10
	// Inner EtherType: IPv4
	pkt[16] = 0x08
	pkt[17] = 0x00

	// IPv4 header
	ip := pkt[18:]
	ip[0] = 0x45
	totalLen := 20 + 20
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// TCP header
	tcp := ip[20:]
	tcp[0] = 0x30 // SrcPort = 0x3039 = 12345
	tcp[1] = 0x39
	tcp[2] = 0x00 // DstPort = 80
	tcp[3] = 0x50
	tcp[12] = 0x50
	tcp[13] = 0x02

	f, ok := decodeEthernet(pkt, time.Now())
	if !ok {
		t.Fatal("decodeEthernet should handle VLAN-tagged packets")
	}
	if f.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", f.Protocol)
	}
	if f.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", f.SrcPort)
	}
	if f.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", f.DstPort)
	}
}

func TestDecodeIPv6(t *testing.T) {
	// Build an Ethernet+IPv6+TCP packet.
	pkt := make([]byte, 14+40+20)
	// EtherType: IPv6
	pkt[12] = 0x86
	pkt[13] = 0xDD

	ip6 := pkt[14:]
	ip6[0] = 0x60 // Version 6
	payloadLen := 20
	ip6[4] = byte(payloadLen >> 8)
	ip6[5] = byte(payloadLen)
	ip6[6] = 6 // Next Header: TCP
	ip6[7] = 64 // Hop Limit

	// Src IPv6: ::1
	ip6[23] = 1
	// Dst IPv6: ::2
	ip6[39] = 2

	// TCP header
	tcp := ip6[40:]
	tcp[0] = 0x1F // SrcPort = 8080
	tcp[1] = 0x90
	tcp[2] = 0x01 // DstPort = 443
	tcp[3] = 0xBB
	tcp[12] = 0x50
	tcp[13] = 0x10 // ACK

	f, ok := decodeEthernet(pkt, time.Now())
	if !ok {
		t.Fatal("decodeEthernet should handle IPv6 packets")
	}
	if f.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", f.Protocol)
	}
	if f.SrcPort != 8080 {
		t.Errorf("SrcPort = %d, want 8080", f.SrcPort)
	}
	if f.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", f.DstPort)
	}
}

func TestSource_ProcessPacket(t *testing.T) {
	var received []model.Flow
	handler := func(flows []model.Flow) {
		received = append(received, flows...)
	}

	cfg := config.InterfaceConfig{
		Name:   "test-mirror",
		Type:   "mirror",
		Device: "eth0",
	}
	src := NewSource(cfg, handler)

	pkt := buildTCPv4Packet(
		net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"),
		12345, 80, 50,
	)
	src.ProcessPacket(pkt, time.Now())

	if len(received) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(received))
	}
	if received[0].DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", received[0].DstPort)
	}
}

func TestSource_ProcessPacket_Invalid(t *testing.T) {
	var received []model.Flow
	handler := func(flows []model.Flow) {
		received = append(received, flows...)
	}

	cfg := config.InterfaceConfig{Name: "test", Type: "mirror", Device: "eth0"}
	src := NewSource(cfg, handler)

	// Send invalid data.
	src.ProcessPacket([]byte{0x00}, time.Now())

	if len(received) != 0 {
		t.Errorf("expected 0 flows for invalid packet, got %d", len(received))
	}
}

func TestSource_DeviceName(t *testing.T) {
	cfg := config.InterfaceConfig{Name: "WAN Mirror", Device: "eth1"}
	src := NewSource(cfg, nil)

	if src.DeviceName() != "eth1" {
		t.Errorf("DeviceName() = %q, want eth1", src.DeviceName())
	}
	if src.InterfaceName() != "WAN Mirror" {
		t.Errorf("InterfaceName() = %q, want WAN Mirror", src.InterfaceName())
	}
}

func TestSource_InterfaceName_Fallback(t *testing.T) {
	cfg := config.InterfaceConfig{Device: "tap0"}
	src := NewSource(cfg, nil)

	if src.InterfaceName() != "tap0" {
		t.Errorf("InterfaceName() = %q, want tap0", src.InterfaceName())
	}
}

func TestSource_StartNoDevice(t *testing.T) {
	cfg := config.InterfaceConfig{Name: "bad", Type: "mirror"}
	src := NewSource(cfg, nil)

	err := src.Start()
	if err == nil {
		t.Error("Start() should fail when device is not configured")
	}
}
