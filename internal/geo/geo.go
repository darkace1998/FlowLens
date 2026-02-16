// Package geo provides pure-Go IP geolocation lookup.
// It supports loading CSV-based GeoIP databases (e.g., ip2location-lite)
// and includes a built-in table of well-known IP ranges for common cloud
// providers and popular services.
package geo

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Info holds the geolocation result for an IP address.
type Info struct {
	Country   string  // ISO 3166-1 alpha-2 country code (e.g. "US")
	City      string  // City name (may be empty)
	Latitude  float64 // WGS-84 latitude
	Longitude float64 // WGS-84 longitude
}

// Lookup provides IP-to-geolocation resolution.
type Lookup struct {
	mu      sync.RWMutex
	entries []rangeEntry // sorted by startIP for binary search
}

// rangeEntry represents a contiguous IP range with geo info.
type rangeEntry struct {
	startIP uint32
	endIP   uint32
	info    Info
}

// New creates a Lookup with built-in well-known IP ranges.
func New() *Lookup {
	l := &Lookup{}
	l.entries = builtinRanges()
	sort.Slice(l.entries, func(i, j int) bool {
		return l.entries[i].startIP < l.entries[j].startIP
	})
	return l
}

// LoadCSV loads a CSV GeoIP database file.
// Expected format: ip_from,ip_to,country_code,country_name,region,city,latitude,longitude
// Lines starting with # or " are treated as comments/headers. This is compatible
// with IP2Location LITE DB5 CSV format.
func (l *Lookup) LoadCSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open geoip csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // variable fields
	r.LazyQuotes = true

	records, err := r.ReadAll()
	if err != nil {
		return fmt.Errorf("parse geoip csv: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, rec := range records {
		if len(rec) < 8 {
			continue
		}
		// Skip header rows.
		if strings.HasPrefix(rec[0], "#") || strings.HasPrefix(rec[0], "ip") {
			continue
		}

		startIP, err1 := parseIPField(rec[0])
		endIP, err2 := parseIPField(rec[1])
		if err1 != nil || err2 != nil {
			continue
		}

		lat, _ := strconv.ParseFloat(strings.TrimSpace(rec[6]), 64)
		lon, _ := strconv.ParseFloat(strings.TrimSpace(rec[7]), 64)

		l.entries = append(l.entries, rangeEntry{
			startIP: startIP,
			endIP:   endIP,
			info: Info{
				Country:   strings.TrimSpace(rec[2]),
				City:      strings.TrimSpace(rec[5]),
				Latitude:  lat,
				Longitude: lon,
			},
		})
	}

	sort.Slice(l.entries, func(i, j int) bool {
		return l.entries[i].startIP < l.entries[j].startIP
	})

	return nil
}

// Find looks up geolocation for an IP address string.
// Returns empty Info{} for private/unresolved IPs.
func (l *Lookup) Find(ipStr string) Info {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Info{}
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return Info{} // IPv6 not supported in this version
	}

	ipNum := binary.BigEndian.Uint32(ip4)

	// Skip private/reserved ranges.
	if isPrivate(ipNum) {
		return Info{Country: "LAN", City: "Private"}
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	// Binary search for the range containing this IP.
	idx := sort.Search(len(l.entries), func(i int) bool {
		return l.entries[i].startIP > ipNum
	})
	// idx is the first entry with startIP > ipNum, so check idx-1.
	if idx > 0 {
		e := l.entries[idx-1]
		if ipNum >= e.startIP && ipNum <= e.endIP {
			return e.info
		}
	}

	return Info{}
}

// parseIPField parses either a dotted-quad IP or a numeric IP string.
func parseIPField(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"")

	// Try dotted-quad first.
	ip := net.ParseIP(s)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			return binary.BigEndian.Uint32(ip4), nil
		}
	}

	// Try numeric.
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n > math.MaxUint32 {
		return 0, fmt.Errorf("IP number out of range: %d", n)
	}
	return uint32(n), nil
}

// isPrivate returns true if the IPv4 address (as uint32) is in a private/reserved range.
func isPrivate(ip uint32) bool {
	// 10.0.0.0/8
	if ip>>24 == 10 {
		return true
	}
	// 172.16.0.0/12
	if ip>>20 == 0xAC1 { // 172.16
		return true
	}
	// 192.168.0.0/16
	if ip>>16 == 0xC0A8 { // 192.168
		return true
	}
	// 127.0.0.0/8
	if ip>>24 == 127 {
		return true
	}
	// 0.0.0.0
	if ip == 0 {
		return true
	}
	return false
}

// builtinRanges returns a set of well-known IP ranges for major services/regions.
// This provides basic geolocation without any external database.
func builtinRanges() []rangeEntry {
	return []rangeEntry{
		// Google DNS
		ipRange("8.8.8.0", "8.8.8.255", "US", "Mountain View", 37.386, -122.084),
		ipRange("8.8.4.0", "8.8.4.255", "US", "Mountain View", 37.386, -122.084),
		// Cloudflare DNS
		ipRange("1.1.1.0", "1.1.1.255", "US", "San Francisco", 37.774, -122.419),
		ipRange("1.0.0.0", "1.0.0.255", "AU", "Sydney", -33.868, 151.207),
		// OpenDNS
		ipRange("208.67.220.0", "208.67.220.255", "US", "San Francisco", 37.774, -122.419),
		ipRange("208.67.222.0", "208.67.222.255", "US", "San Francisco", 37.774, -122.419),
		// AWS us-east-1
		ipRange("3.0.0.0", "3.127.255.255", "US", "Ashburn", 39.046, -77.487),
		// AWS eu-west-1
		ipRange("3.248.0.0", "3.255.255.255", "IE", "Dublin", 53.349, -6.260),
		// Azure US
		ipRange("13.64.0.0", "13.107.255.255", "US", "Redmond", 47.674, -122.121),
		// Azure EU
		ipRange("40.112.0.0", "40.127.255.255", "NL", "Amsterdam", 52.377, 4.895),
		// Google Cloud US
		ipRange("35.192.0.0", "35.207.255.255", "US", "Council Bluffs", 41.262, -95.861),
		// Google Cloud EU
		ipRange("35.208.0.0", "35.223.255.255", "BE", "St-Ghislain", 50.448, 3.818),
		// Akamai
		ipRange("23.0.0.0", "23.79.255.255", "US", "Cambridge", 42.365, -71.105),
		// Fastly
		ipRange("151.101.0.0", "151.101.255.255", "US", "San Francisco", 37.774, -122.419),
		// GitHub
		ipRange("140.82.112.0", "140.82.127.255", "US", "San Francisco", 37.774, -122.419),
		// Microsoft
		ipRange("20.33.0.0", "20.128.255.255", "US", "Redmond", 47.674, -122.121),
		// Facebook/Meta
		ipRange("157.240.0.0", "157.240.255.255", "US", "Menlo Park", 37.453, -122.182),
		ipRange("31.13.24.0", "31.13.127.255", "US", "Menlo Park", 37.453, -122.182),
		// Twitter/X
		ipRange("104.244.40.0", "104.244.47.255", "US", "San Francisco", 37.774, -122.419),
		// Netflix
		ipRange("69.53.224.0", "69.53.255.255", "US", "Los Gatos", 37.225, -121.976),
		// Apple
		ipRange("17.0.0.0", "17.255.255.255", "US", "Cupertino", 37.323, -122.032),
		// Quad9 DNS
		ipRange("9.9.9.0", "9.9.9.255", "CH", "Zurich", 47.377, 8.541),
		// OVH EU
		ipRange("51.38.0.0", "51.38.255.255", "FR", "Roubaix", 50.693, 3.174),
		ipRange("51.68.0.0", "51.68.255.255", "FR", "Gravelines", 50.987, 2.128),
		// Hetzner
		ipRange("95.216.0.0", "95.216.255.255", "FI", "Helsinki", 60.170, 24.938),
		ipRange("78.46.0.0", "78.47.255.255", "DE", "Falkenstein", 50.478, 12.337),
		// Alibaba Cloud
		ipRange("47.88.0.0", "47.91.255.255", "CN", "Hangzhou", 30.274, 120.155),
		// Tencent Cloud
		ipRange("119.28.0.0", "119.29.255.255", "CN", "Shenzhen", 22.543, 114.058),
		// NTT Japan
		ipRange("210.160.0.0", "210.175.255.255", "JP", "Tokyo", 35.690, 139.692),
		// Telstra Australia
		ipRange("203.0.0.0", "203.63.255.255", "AU", "Sydney", -33.868, 151.207),
	}
}

// ipRange creates a rangeEntry from dotted-quad start/end IPs.
func ipRange(startStr, endStr, country, city string, lat, lon float64) rangeEntry {
	startIP := net.ParseIP(startStr).To4()
	endIP := net.ParseIP(endStr).To4()
	return rangeEntry{
		startIP: binary.BigEndian.Uint32(startIP),
		endIP:   binary.BigEndian.Uint32(endIP),
		info: Info{
			Country:   country,
			City:      city,
			Latitude:  lat,
			Longitude: lon,
		},
	}
}
