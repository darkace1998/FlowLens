package model

import (
	"fmt"
	"net"
	"time"
)

// Flow represents a unified flow record decoded from any NetFlow/IPFIX version.
type Flow struct {
	Timestamp   time.Time
	SrcAddr     net.IP
	DstAddr     net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8 // TCP=6, UDP=17, ICMP=1, etc.
	Bytes       uint64
	Packets     uint64
	TCPFlags    uint8
	ToS         uint8
	InputIface  uint32
	OutputIface uint32
	SrcAS       uint32
	DstAS       uint32
	Duration    time.Duration
	ExporterIP  net.IP // which device sent this flow
}

// ProtocolName returns a human-readable name for common IP protocol numbers.
func ProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Proto(%d)", proto)
	}
}

// String returns a brief summary of the flow record.
func (f Flow) String() string {
	return fmt.Sprintf("%s %s:%d → %s:%d %s %d bytes %d pkts",
		f.Timestamp.Format(time.RFC3339),
		f.SrcAddr, f.SrcPort,
		f.DstAddr, f.DstPort,
		ProtocolName(f.Protocol),
		f.Bytes, f.Packets,
	)
}

// SafeIPString converts a net.IP to string, returning "0.0.0.0" for nil IPs.
func SafeIPString(ip net.IP) string {
	if ip == nil {
		return "0.0.0.0"
	}
	return ip.String()
}
