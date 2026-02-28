package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all FlowLens configuration.
type Config struct {
	Collector CollectorConfig `yaml:"collector"`
	Storage   StorageConfig   `yaml:"storage"`
	Analysis  AnalysisConfig  `yaml:"analysis"`
	Web       WebConfig       `yaml:"web"`
	Capture   CaptureConfig   `yaml:"capture"`
}

// CollectorConfig holds settings for the NetFlow/IPFIX/sFlow collector.
type CollectorConfig struct {
	NetFlowPort    int               `yaml:"netflow_port"`
	IPFIXPort      int               `yaml:"ipfix_port"`
	SFlowPort      int               `yaml:"sflow_port"`     // UDP port for sFlow v5 (default: 6343)
	BufferSize     int               `yaml:"buffer_size"`
	InterfaceNames map[string]string `yaml:"interface_names"` // ifIndex → human-readable name (e.g. "1": "eth0")
	Interfaces     []InterfaceConfig `yaml:"interfaces"`      // multiple collector instances bound to different addresses
}

// InterfaceConfig defines a single collector listener bound to a specific address/port.
type InterfaceConfig struct {
	Name    string `yaml:"name"`    // human-readable name (e.g. "WAN", "LAN", "Mirror")
	Listen  string `yaml:"listen"`  // bind address (e.g. ":2055", "192.168.1.1:4739")
	Type    string `yaml:"type"`    // "netflow" (default), "mirror", or "tap"
	Device  string `yaml:"device"`  // network device for mirror/tap mode (e.g. "eth1", "tap0")
	BPF     string `yaml:"bpf"`     // optional BPF filter for mirror/tap capture
	SnapLen int    `yaml:"snaplen"` // packet snapshot length for mirror/tap (default: 65535)
}

// StorageConfig holds settings for flow data storage.
type StorageConfig struct {
	RingBufferDuration time.Duration `yaml:"ring_buffer_duration"`
	RingBufferCapacity int           `yaml:"ring_buffer_capacity"` // max records in ring buffer (default: 10000)
	SQLitePath         string        `yaml:"sqlite_path"`
	SQLiteRetention    time.Duration `yaml:"sqlite_retention"`
	PruneInterval      time.Duration `yaml:"prune_interval"`
	GeoIPPath          string        `yaml:"geoip_path"` // optional path to CSV GeoIP database (e.g. IP2Location LITE)
}

// AnalysisConfig holds settings for the analysis engine.
type AnalysisConfig struct {
	Interval              time.Duration `yaml:"interval"`
	TopTalkersCount       int           `yaml:"top_talkers_count"`
	AnomalyBaselineWindow time.Duration `yaml:"anomaly_baseline_window"`
	ScanThreshold         int           `yaml:"scan_threshold"`
	QueryWindow           time.Duration `yaml:"query_window"` // analysis query window (defaults to ring_buffer_duration)
}

// WebConfig holds settings for the web server.
type WebConfig struct {
	Listen   string `yaml:"listen"`
	PageSize int    `yaml:"page_size"`
}

// CaptureConfig holds settings for packet capture and PCAP storage.
type CaptureConfig struct {
	Interfaces []string `yaml:"interfaces"` // network interfaces available for capture (e.g. ["eth0", "eth1"])
	SnapLen    int      `yaml:"snaplen"`    // packet snapshot length (default: 65535)
	Dir        string   `yaml:"dir"`        // directory to store PCAP files (default: "./captures")
	MaxSizeMB  int      `yaml:"max_size_mb"` // max PCAP file size in MB before rotation (default: 100)
	MaxFiles   int      `yaml:"max_files"`   // max number of PCAP files to keep (default: 10)
}

// Defaults returns a Config populated with sensible default values.
func Defaults() Config {
	return Config{
		Collector: CollectorConfig{
			NetFlowPort: 2055,
			IPFIXPort:   4739,
			SFlowPort:   6343,
			BufferSize:  65535,
		},
		Storage: StorageConfig{
			RingBufferDuration: 10 * time.Minute,
			RingBufferCapacity: 10000,
			SQLitePath:         "./flowlens.db",
			SQLiteRetention:    72 * time.Hour,
			PruneInterval:      15 * time.Minute,
		},
		Analysis: AnalysisConfig{
			Interval:              60 * time.Second,
			TopTalkersCount:       10,
			AnomalyBaselineWindow: 7 * 24 * time.Hour,
			ScanThreshold:         500,
		},
		Web: WebConfig{
			Listen:   ":8080",
			PageSize: 50,
		},
		Capture: CaptureConfig{
			SnapLen:   65535,
			Dir:       "./captures",
			MaxSizeMB: 100,
			MaxFiles:  10,
		},
	}
}

// Load reads a YAML configuration file from path and returns a Config.
// Values not specified in the file retain their defaults.
func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config file: %w", err)
	}

	return cfg, nil
}
