package capture

import (
	"bytes"
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
	ip[8] = 64 // TTL
	ip[9] = 6  // Protocol: TCP
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
	// L2 fields should be populated from Ethernet header.
	if len(f.SrcMAC) != 6 {
		t.Errorf("SrcMAC length = %d, want 6", len(f.SrcMAC))
	}
	if len(f.DstMAC) != 6 {
		t.Errorf("DstMAC length = %d, want 6", len(f.DstMAC))
	}
	if f.EtherType != 0x0800 {
		t.Errorf("EtherType = 0x%04X, want 0x0800 (IPv4)", f.EtherType)
	}
	if f.VLAN != 0 {
		t.Errorf("VLAN = %d, want 0 (untagged)", f.VLAN)
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
	if f.VLAN != 10 {
		t.Errorf("VLAN = %d, want 10", f.VLAN)
	}
	if f.EtherType != 0x0800 {
		t.Errorf("EtherType = 0x%04X, want 0x0800", f.EtherType)
	}
	expectedSrcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if !bytes.Equal(f.SrcMAC, expectedSrcMAC) {
		t.Errorf("SrcMAC = %s, want %s", f.SrcMAC, expectedSrcMAC)
	}
	expectedDstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(f.DstMAC, expectedDstMAC) {
		t.Errorf("DstMAC = %s, want %s", f.DstMAC, expectedDstMAC)
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
	ip6[6] = 6  // Next Header: TCP
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

// buildICMPv4Packet constructs a minimal Ethernet+IPv4+ICMP packet for testing.
func buildICMPv4Packet(srcIP, dstIP net.IP, payloadLen int) []byte {
	pkt := make([]byte, 14+20+8+payloadLen) // eth + ip + icmp + payload
	pkt[12] = 0x08
	pkt[13] = 0x00

	ip := pkt[14:]
	ip[0] = 0x45
	totalLen := 20 + 8 + payloadLen
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[8] = 64
	ip[9] = 1 // Protocol: ICMP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	return pkt
}

// buildTCPv6Packet constructs a minimal Ethernet+IPv6+TCP packet for testing.
func buildTCPv6Packet(srcIP, dstIP net.IP, srcPort, dstPort uint16, payloadLen int) []byte {
	pkt := make([]byte, 14+40+20+payloadLen) // eth + ip6 + tcp + payload
	pkt[12] = 0x86
	pkt[13] = 0xDD

	ip6 := pkt[14:]
	ip6[0] = 0x60 // Version 6
	payloadLenField := 20 + payloadLen
	ip6[4] = byte(payloadLenField >> 8)
	ip6[5] = byte(payloadLenField)
	ip6[6] = 6  // Next Header: TCP
	ip6[7] = 64 // Hop Limit
	copy(ip6[8:24], srcIP.To16())
	copy(ip6[24:40], dstIP.To16())

	tcp := ip6[40:]
	tcp[0] = byte(srcPort >> 8)
	tcp[1] = byte(srcPort)
	tcp[2] = byte(dstPort >> 8)
	tcp[3] = byte(dstPort)
	tcp[12] = 0x50
	tcp[13] = 0x02

	return pkt
}

// vlanWrap prepends an 802.1Q tag (TPID 0x8100, given VLAN ID) to an Ethernet frame.
func vlanWrap(frame []byte, vlanID uint16) []byte {
	tagged := make([]byte, 4+len(frame))
	copy(tagged, frame[:12])
	tagged[12] = 0x81
	tagged[13] = 0x00
	tagged[14] = byte(vlanID >> 8)
	tagged[15] = byte(vlanID)
	copy(tagged[16:], frame[12:])
	return tagged
}

func TestCompileBPF_TCPPort80(t *testing.T) {
	filt, err := compileBPF("tcp port 80")
	if err != nil {
		t.Fatalf("compileBPF: %v", err)
	}

	tcp80 := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"), 12345, 80, 10)
	if !filt(tcp80) {
		t.Error("expected TCP packet with dst port 80 to match \"tcp port 80\"")
	}

	tcp443 := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"), 12345, 443, 10)
	if filt(tcp443) {
		t.Error("TCP packet with dst port 443 should not match \"tcp port 80\"")
	}

	udp80 := buildUDPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"), 12345, 80, 10)
	if filt(udp80) {
		t.Error("UDP packet with dst port 80 should not match \"tcp port 80\"")
	}

	// Source port also matches.
	tcpSrc80 := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1"), 80, 12345, 10)
	if !filt(tcpSrc80) {
		t.Error("expected TCP packet with src port 80 to match \"tcp port 80\"")
	}
}

func TestCompileBPF_UDPAndHost(t *testing.T) {
	filt, err := compileBPF("udp and host 10.0.0.1")
	if err != nil {
		t.Fatalf("compileBPF: %v", err)
	}

	udpFrom := buildUDPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 53, 5353, 10)
	if !filt(udpFrom) {
		t.Error("expected UDP packet from 10.0.0.1 to match")
	}

	udpOther := buildUDPv4Packet(net.ParseIP("10.0.0.2"), net.ParseIP("8.8.8.8"), 53, 5353, 10)
	if filt(udpOther) {
		t.Error("UDP packet from 10.0.0.2 should not match \"udp and host 10.0.0.1\"")
	}

	tcpFrom := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 53, 5353, 10)
	if filt(tcpFrom) {
		t.Error("TCP packet from 10.0.0.1 should not match \"udp and host 10.0.0.1\"")
	}
}

func TestCompileBPF_NotICMP(t *testing.T) {
	filt, err := compileBPF("not icmp")
	if err != nil {
		t.Fatalf("compileBPF: %v", err)
	}

	icmp := buildICMPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 8)
	if filt(icmp) {
		t.Error("ICMP packet should not match \"not icmp\"")
	}

	tcp := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1000, 80, 8)
	if !filt(tcp) {
		t.Error("TCP packet should match \"not icmp\"")
	}
}

func TestCompileBPF_Net(t *testing.T) {
	filt, err := compileBPF("net 10.0.0.0/8")
	if err != nil {
		t.Fatalf("compileBPF: %v", err)
	}

	inNet := buildTCPv4Packet(net.ParseIP("10.20.30.40"), net.ParseIP("192.168.1.1"), 1, 2, 0)
	if !filt(inNet) {
		t.Error("expected packet from 10.20.30.40 to match \"net 10.0.0.0/8\"")
	}

	outNet := buildTCPv4Packet(net.ParseIP("11.0.0.1"), net.ParseIP("192.168.1.1"), 1, 2, 0)
	if filt(outNet) {
		t.Error("packet from 11.0.0.1 should not match \"net 10.0.0.0/8\"")
	}
}

func TestCompileBPF_SrcHostAndDstPort(t *testing.T) {
	filt, err := compileBPF("src host 192.168.1.1 and dst port 443")
	if err != nil {
		t.Fatalf("compileBPF: %v", err)
	}

	match := buildTCPv4Packet(net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1"), 5000, 443, 0)
	if !filt(match) {
		t.Error("expected src 192.168.1.1 dst port 443 to match")
	}

	wrongPort := buildTCPv4Packet(net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1"), 5000, 80, 0)
	if filt(wrongPort) {
		t.Error("dst port 80 should not match \"src host 192.168.1.1 and dst port 443\"")
	}

	wrongSrc := buildTCPv4Packet(net.ParseIP("192.168.1.2"), net.ParseIP("10.0.0.1"), 5000, 443, 0)
	if filt(wrongSrc) {
		t.Error("src 192.168.1.2 should not match \"src host 192.168.1.1 and dst port 443\"")
	}
}

func TestCompileBPF_GreaterLess(t *testing.T) {
	greater, err := compileBPF("greater 100")
	if err != nil {
		t.Fatalf("compileBPF greater: %v", err)
	}
	less, err := compileBPF("less 100")
	if err != nil {
		t.Fatalf("compileBPF less: %v", err)
	}

	big := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2, 100) // 154 bytes
	small := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2, 10) // 64 bytes

	if !greater(big) {
		t.Error("154-byte frame should match \"greater 100\"")
	}
	if greater(small) {
		t.Error("64-byte frame should not match \"greater 100\"")
	}
	if !less(small) {
		t.Error("64-byte frame should match \"less 100\"")
	}
	if less(big) {
		t.Error("154-byte frame should not match \"less 100\"")
	}
}

func TestCompileBPF_ParensOrAnd(t *testing.T) {
	filt, err := compileBPF("(tcp port 80 or udp port 53) and host 10.0.0.1")
	if err != nil {
		t.Fatalf("compileBPF: %v", err)
	}

	tcp80 := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 1, 80, 0)
	udp53 := buildUDPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 1, 53, 0)
	tcp443 := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8"), 1, 443, 0)
	tcp80Other := buildTCPv4Packet(net.ParseIP("10.0.0.9"), net.ParseIP("8.8.8.8"), 1, 80, 0)

	if !filt(tcp80) || !filt(udp53) {
		t.Error("tcp/80 and udp/53 from 10.0.0.1 should match")
	}
	if filt(tcp443) {
		t.Error("tcp/443 should not match")
	}
	if filt(tcp80Other) {
		t.Error("tcp/80 from 10.0.0.9 should not match (host qualifier)")
	}
}

func TestCompileBPF_VLANTagged(t *testing.T) {
	filt, err := compileBPF("tcp port 80")
	if err != nil {
		t.Fatalf("compileBPF: %v", err)
	}

	inner := buildTCPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 80, 10)
	tagged := vlanWrap(vlanWrap(inner, 20), 10) // stacked Q-in-Q tags
	if !filt(tagged) {
		t.Error("VLAN-tagged TCP port 80 packet should match \"tcp port 80\"")
	}
}

func TestCompileBPF_IPv6(t *testing.T) {
	filt, err := compileBPF("tcp port 443")
	if err != nil {
		t.Fatalf("compileBPF: %v", err)
	}

	pkt := buildTCPv6Packet(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 8080, 443, 10)
	if !filt(pkt) {
		t.Error("IPv6 TCP packet with dst port 443 should match \"tcp port 443\"")
	}

	udp := buildTCPv6Packet(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 8080, 443, 10)
	udp[14+6] = 17 // UDP next header
	if filt(udp) {
		t.Error("IPv6 UDP packet should not match \"tcp port 443\"")
	}
}

func TestCompileBPF_Invalid(t *testing.T) {
	exprs := []string{
		"",
		"tcp port",           // missing port value
		"host",               // missing host value
		"(tcp",               // unbalanced paren
		"tcp)",               // unbalanced paren
		"port abc",           // non-numeric port
		"foo bar",            // unsupported token
		"net 10.0.0.0/33",    // prefix too large for IPv4
		"host 999.1.1.1",     // invalid IP
		"tcp udp port 80",    // multiple protocol qualifiers
		"greater",            // missing length value
		"not",                // dangling not
		"arp host 10.0.0.1",  // arp cannot combine with host
	}
	for _, expr := range exprs {
		if _, err := compileBPF(expr); err == nil {
			t.Errorf("compileBPF(%q) should return an error, got nil", expr)
		}
	}
}

func TestDecodeEthernet_StackedVLAN(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("10.0.0.2")

	// Q-in-Q: outer 802.1ad tag (0x88a8, VLAN 20), inner 802.1Q tag (0x8100, VLAN 10).
	pkt := make([]byte, 14+4+4+20+20) // eth + 2 tags + ip + tcp
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	pkt[12] = 0x88
	pkt[13] = 0xa8
	pkt[14] = 0x00
	pkt[15] = 0x14 // outer TCI → VLAN 20
	pkt[16] = 0x81
	pkt[17] = 0x00
	pkt[18] = 0x00
	pkt[19] = 0x0A // inner TCI → VLAN 10
	pkt[20] = 0x08
	pkt[21] = 0x00 // inner EtherType: IPv4

	ip := pkt[22:]
	ip[0] = 0x45
	totalLen := 20 + 20
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	tcp := ip[20:]
	tcp[0] = 0x30
	tcp[1] = 0x39 // SrcPort = 12345
	tcp[2] = 0x00
	tcp[3] = 0x50 // DstPort = 80
	tcp[12] = 0x50
	tcp[13] = 0x02

	f, ok := decodeEthernet(pkt, time.Now())
	if !ok {
		t.Fatal("decodeEthernet should handle stacked VLAN tags")
	}
	if f.VLAN != 10 {
		t.Errorf("VLAN = %d, want 10 (innermost tag)", f.VLAN)
	}
	if f.EtherType != 0x0800 {
		t.Errorf("EtherType = 0x%04X, want 0x0800 (IPv4)", f.EtherType)
	}
	if f.SrcPort != 12345 || f.DstPort != 80 {
		t.Errorf("ports = %d/%d, want 12345/80", f.SrcPort, f.DstPort)
	}
	if f.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", f.Protocol)
	}
}

func TestDecodeEthernet_VLANTruncated(t *testing.T) {
	// EtherType says 802.1Q but the tag is cut off.
	pkt := make([]byte, 16)
	pkt[12] = 0x81
	pkt[13] = 0x00

	if _, ok := decodeEthernet(pkt, time.Now()); ok {
		t.Error("decodeEthernet should return false for a truncated VLAN tag")
	}
}

func TestDecodeIPv6_ExtHeaderAndTTL(t *testing.T) {
	// IPv6 + hop-by-hop extension header (8 bytes) + TCP.
	pkt := make([]byte, 14+40+8+20)
	pkt[12] = 0x86
	pkt[13] = 0xDD

	ip6 := pkt[14:]
	ip6[0] = 0x60
	payloadLen := 8 + 20
	ip6[4] = byte(payloadLen >> 8)
	ip6[5] = byte(payloadLen)
	ip6[6] = 0  // Next Header: hop-by-hop options
	ip6[7] = 64 // Hop Limit
	// Src IPv6: 2001:db8::1
	copy(ip6[8:24], net.ParseIP("2001:db8::1").To16())
	// Dst IPv6: 2001:db8::2
	copy(ip6[24:40], net.ParseIP("2001:db8::2").To16())

	// Hop-by-hop header: next header = TCP, hdr ext len = 0 (8 bytes total).
	ext := ip6[40:]
	ext[0] = 6
	ext[1] = 0

	// TCP header after the extension header.
	tcp := ip6[48:]
	tcp[0] = 0x1F
	tcp[1] = 0x90 // SrcPort = 8080
	tcp[2] = 0x01
	tcp[3] = 0xBB // DstPort = 443
	tcp[12] = 0x50
	tcp[13] = 0x10 // ACK

	f, ok := decodeEthernet(pkt, time.Now())
	if !ok {
		t.Fatal("decodeEthernet should handle IPv6 packets with extension headers")
	}
	if f.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP after ext header walk)", f.Protocol)
	}
	if f.SrcPort != 8080 || f.DstPort != 443 {
		t.Errorf("ports = %d/%d, want 8080/443", f.SrcPort, f.DstPort)
	}
	if f.TCPFlags != 0x10 {
		t.Errorf("TCPFlags = 0x%02x, want 0x10 (ACK)", f.TCPFlags)
	}
	if f.TTL != 64 {
		t.Errorf("TTL = %d, want 64 (hop limit)", f.TTL)
	}
}

func TestDecodeIPv6_TruncatedExtHeader(t *testing.T) {
	// Hop-by-hop header claims 8 bytes but the frame ends early: must not panic,
	// and the flow is still decoded (without L4 ports).
	pkt := make([]byte, 14+40+2)
	pkt[12] = 0x86
	pkt[13] = 0xDD
	ip6 := pkt[14:]
	ip6[0] = 0x60
	ip6[6] = 0 // hop-by-hop
	ip6[7] = 32
	ext := ip6[40:]
	ext[0] = 6
	ext[1] = 0

	f, ok := decodeEthernet(pkt, time.Now())
	if !ok {
		t.Fatal("decodeEthernet should still decode a truncated ext-header packet")
	}
	if f.SrcPort != 0 || f.DstPort != 0 {
		t.Errorf("ports = %d/%d, want 0/0 when L4 is unreachable", f.SrcPort, f.DstPort)
	}
	if f.TTL != 32 {
		t.Errorf("TTL = %d, want 32", f.TTL)
	}
}
