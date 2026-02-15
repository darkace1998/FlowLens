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
