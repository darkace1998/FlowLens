package geo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFind_PrivateIPs(t *testing.T) {
	l := New()
	tests := []struct {
		ip      string
		country string
	}{
		{"10.0.0.1", "LAN"},
		{"192.168.1.1", "LAN"},
		{"172.16.0.1", "LAN"},
		{"127.0.0.1", "LAN"},
		{"0.0.0.0", "LAN"},
	}
	for _, tt := range tests {
		info := l.Find(tt.ip)
		if info.Country != tt.country {
			t.Errorf("Find(%q).Country = %q, want %q", tt.ip, info.Country, tt.country)
		}
	}
}

func TestFind_BuiltinRanges(t *testing.T) {
	l := New()
	tests := []struct {
		ip      string
		country string
		city    string
	}{
		{"8.8.8.8", "US", "Mountain View"},
		{"1.1.1.1", "US", "San Francisco"},
		{"9.9.9.9", "CH", "Zurich"},
		{"17.172.224.47", "US", "Cupertino"},
	}
	for _, tt := range tests {
		info := l.Find(tt.ip)
		if info.Country != tt.country {
			t.Errorf("Find(%q).Country = %q, want %q", tt.ip, info.Country, tt.country)
		}
		if info.City != tt.city {
			t.Errorf("Find(%q).City = %q, want %q", tt.ip, info.City, tt.city)
		}
	}
}

func TestFind_UnknownIP(t *testing.T) {
	l := New()
	info := l.Find("100.100.100.100")
	if info.Country != "" {
		t.Errorf("Find(unknown).Country = %q, want empty", info.Country)
	}
}

func TestFind_InvalidIP(t *testing.T) {
	l := New()
	info := l.Find("not-an-ip")
	if info.Country != "" {
		t.Errorf("Find(invalid).Country = %q, want empty", info.Country)
	}
}

func TestFind_IPv6(t *testing.T) {
	l := New()
	info := l.Find("::1")
	if info.Country != "" {
		t.Errorf("Find(ipv6).Country = %q, want empty", info.Country)
	}
}

func TestLoadCSV(t *testing.T) {
	// Create a temp CSV file.
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "test-geo.csv")
	content := `"16777216","16777471","AU","Australia","Queensland","Brisbane","-27.467","153.028"
"16777472","16778239","CN","China","Fujian","Fuzhou","26.061","119.306"
`
	if err := os.WriteFile(csvPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	l := New()
	if err := l.LoadCSV(csvPath); err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	// 16777216 = 1.0.0.0
	info := l.Find("1.0.0.100")
	if info.Country != "AU" {
		t.Errorf("Find(1.0.0.100).Country = %q, want AU", info.Country)
	}
	if info.City != "Brisbane" {
		t.Errorf("Find(1.0.0.100).City = %q, want Brisbane", info.City)
	}
}

func TestLoadCSV_DottedQuad(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "test-geo.csv")
	content := `"200.0.0.0","200.0.0.255","BR","Brazil","Sao Paulo","Sao Paulo","-23.547","-46.636"
`
	if err := os.WriteFile(csvPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	l := New()
	if err := l.LoadCSV(csvPath); err != nil {
		t.Fatalf("LoadCSV: %v", err)
	}

	info := l.Find("200.0.0.1")
	if info.Country != "BR" {
		t.Errorf("Find(200.0.0.1).Country = %q, want BR", info.Country)
	}
}

func TestLoadCSV_MissingFile(t *testing.T) {
	l := New()
	err := l.LoadCSV("/nonexistent/path.csv")
	if err == nil {
		t.Error("LoadCSV should return error for missing file")
	}
}

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.0", false},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
	}
	for _, tt := range tests {
		ip4 := parseIPv4(tt.ip)
		got := isPrivate(ip4)
		if got != tt.want {
			t.Errorf("isPrivate(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func parseIPv4(s string) uint32 {
	ip, err := parseIPField(s)
	if err != nil {
		panic(err)
	}
	return ip
}
