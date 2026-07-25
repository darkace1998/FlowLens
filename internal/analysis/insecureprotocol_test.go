package analysis

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/darkace1998/FlowLens/internal/model"
	"github.com/darkace1998/FlowLens/internal/storage"
)

func TestInsecureProtocolDetector(t *testing.T) {
	tests := []struct {
		name         string
		flows        []model.Flow
		wantAdvisory bool
		wantService  string
		wantTitle    string
	}{
		{
			name: "telnet traffic",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("10.0.0.1"),
					DstAddr:   net.ParseIP("192.168.1.100"),
					Protocol:  6,
					DstPort:   23, // Telnet
					Bytes:     500,
				},
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("10.0.0.2"),
					DstAddr:   net.ParseIP("192.168.1.100"),
					Protocol:  6,
					DstPort:   23, // Telnet
					Bytes:     500,
				},
			},
			wantAdvisory: true,
			wantService:  "Telnet",
			wantTitle:    "Insecure Protocol Usage: Telnet",
		},
		{
			name: "ftp traffic",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("10.0.0.1"),
					DstAddr:   net.ParseIP("192.168.1.100"),
					Protocol:  6,
					DstPort:   21, // FTP
					Bytes:     1500,
				},
			},
			wantAdvisory: true,
			wantService:  "FTP",
			wantTitle:    "Insecure Protocol Usage: FTP",
		},
		{
			name: "secure traffic",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("10.0.0.1"),
					DstAddr:   net.ParseIP("192.168.1.100"),
					Protocol:  6,
					DstPort:   22, // SSH
					Bytes:     5000,
				},
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("10.0.0.2"),
					DstAddr:   net.ParseIP("192.168.1.100"),
					Protocol:  6,
					DstPort:   443, // HTTPS
					Bytes:     5000,
				},
			},
			wantAdvisory: false,
		},
		{
			name: "tftp traffic",
			flows: []model.Flow{
				{
					Timestamp: time.Now(),
					SrcAddr:   net.ParseIP("10.0.0.1"),
					DstAddr:   net.ParseIP("192.168.1.100"),
					Protocol:  17, // UDP
					DstPort:   69, // TFTP
					Bytes:     1000,
				},
			},
			wantAdvisory: true,
			wantService:  "TFTP",
			wantTitle:    "Insecure Protocol Usage: TFTP",
		},
	}

	detector := InsecureProtocolDetector{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storage.NewRingBuffer(100)
			_ = store.Insert(tt.flows)

			advisories := detector.Analyze(store, defaultCfg())

			if !tt.wantAdvisory {
				if len(advisories) != 0 {
					t.Fatalf("expected 0 advisories, got %d", len(advisories))
				}
				return
			}

			if len(advisories) == 0 {
				t.Fatalf("expected at least 1 advisory, got 0")
			}

			found := false
			for _, adv := range advisories {
				if adv.Severity == WARNING && strings.Contains(adv.Title, tt.wantService) {
					found = true
					if adv.Title != tt.wantTitle {
						t.Errorf("expected title %q, got %q", tt.wantTitle, adv.Title)
					}
					if !strings.Contains(adv.Description, "cleartext") {
						t.Errorf("expected description to contain 'cleartext', got %q", adv.Description)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected advisory for service %s, not found in %v", tt.wantService, advisories)
			}
		})
	}
}

func TestInsecureProtocolDetector_Error(t *testing.T) {
	detector := InsecureProtocolDetector{}
	advisories := detector.Analyze(mockErrorStorage{}, defaultCfg())
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on storage error, got %d", len(advisories))
	}
}
