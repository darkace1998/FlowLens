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
