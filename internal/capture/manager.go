package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/darkace1998/FlowLens/internal/config"
	"github.com/darkace1998/FlowLens/internal/logging"
)

// SessionState represents the state of a capture session.
type SessionState string

const (
	StateRunning SessionState = "running"
	StateStopped SessionState = "stopped"
)

// Session represents an active or completed capture session.
type Session struct {
	ID        string
	Device    string
	BPF       string
	SnapLen   int
	State     SessionState
	StartTime time.Time
	StopTime  time.Time
	Packets   int64
	Bytes     int64
	FileName  string // current PCAP file name prefix
}

// Manager manages packet capture sessions, coordinating between the
// raw packet capture (Source) and PCAP file writing (PcapWriter).
type Manager struct {
	mu       sync.Mutex
	cfg      config.CaptureConfig
	sessions map[string]*activeSession
	counter  int
}

type activeSession struct {
	session Session
	source  *Source
	writer  *PcapWriter
	stopCh  chan struct{}
}

// NewManager creates a new capture manager.
func NewManager(cfg config.CaptureConfig) *Manager {
	return &Manager{
		cfg:      cfg,
		sessions: make(map[string]*activeSession),
	}
}

// Start begins a new capture session on the specified device with an optional BPF filter.
func (m *Manager) Start(device, bpf string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate session ID.
	m.counter++
	id := fmt.Sprintf("cap-%d", m.counter)

	snapLen := m.cfg.SnapLen
	if snapLen <= 0 {
		snapLen = 65535
	}

	// Create PCAP writer.
	prefix := fmt.Sprintf("%s_%s", id, device)
	writer, err := NewPcapWriter(m.cfg.Dir, prefix, uint32(snapLen), m.cfg.MaxSizeMB, m.cfg.MaxFiles)
	if err != nil {
		return "", fmt.Errorf("capture manager: %w", err)
	}

	// Create a capture source that writes packets to the PCAP file.
	ifCfg := config.InterfaceConfig{
		Name:    id,
		Type:    "mirror",
		Device:  device,
		BPF:     bpf,
		SnapLen: snapLen,
	}

	stopCh := make(chan struct{})

	// The handler writes each packet to the PCAP file.
	// We wrap the source's ProcessPacket to also write raw data to PCAP.
	src := NewSource(ifCfg, nil)

	as := &activeSession{
		session: Session{
			ID:        id,
			Device:    device,
			BPF:       bpf,
			SnapLen:   snapLen,
			State:     StateRunning,
			StartTime: time.Now(),
			FileName:  prefix,
		},
		source: src,
		writer: writer,
		stopCh: stopCh,
	}

	m.sessions[id] = as

	// Start capture in a goroutine.
	go func() {
		if err := m.runCapture(as); err != nil {
			logging.Default().Error("Capture %s error: %v", id, err)
		}
	}()

	return id, nil
}

// runCapture performs the actual capture using a raw socket and writes packets
// to the PCAP file.
func (m *Manager) runCapture(as *activeSession) error {
	pcapWriter := as.writer

	handler := func(data []byte, ts time.Time) {
		if err := pcapWriter.WritePacket(data, ts); err != nil {
			logging.Default().Warn("PCAP write error: %v", err)
		}
	}

	ifCfg := as.source.cfg
	snapLen := ifCfg.SnapLen
	if snapLen <= 0 {
		snapLen = 65535
	}

	return runRawCapture(ifCfg.Device, snapLen, handler, as.stopCh)
}

// Stop stops a capture session.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	as, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("capture session %q not found", id)
	}
	m.mu.Unlock()

	// Signal stop.
	select {
	case <-as.stopCh:
		// Already stopped.
	default:
		close(as.stopCh)
	}

	// Close PCAP writer.
	as.writer.Close()

	// Update session state.
	m.mu.Lock()
	pkts, bytes := as.writer.Stats()
	as.session.State = StateStopped
	as.session.StopTime = time.Now()
	as.session.Packets = pkts
	as.session.Bytes = bytes
	m.mu.Unlock()

	return nil
}

// Sessions returns a copy of all capture sessions.
func (m *Manager) Sessions() []Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]Session, 0, len(m.sessions))
	for _, as := range m.sessions {
		s := as.session
		if s.State == StateRunning {
			pkts, bytes := as.writer.Stats()
			s.Packets = pkts
			s.Bytes = bytes
		}
		result = append(result, s)
	}
	return result
}

// PcapDir returns the configured capture directory.
func (m *Manager) PcapDir() string {
	return m.cfg.Dir
}

// PcapFiles returns the list of available PCAP files.
func (m *Manager) PcapFiles() ([]PcapFileInfo, error) {
	return ListPcapFiles(m.cfg.Dir)
}

// PcapFilePath returns the full path to a PCAP file, validating it exists in the capture dir.
func (m *Manager) PcapFilePath(name string) (string, error) {
	// Prevent path traversal.
	clean := filepath.Base(name)
	if clean != name || clean == "." || clean == ".." {
		return "", fmt.Errorf("invalid filename: %q", name)
	}

	path := filepath.Join(m.cfg.Dir, clean)
	if _, err := pathStat(path); err != nil {
		return "", fmt.Errorf("pcap file not found: %q", name)
	}
	return path, nil
}

// pathStat wraps os.Stat for testing.
var pathStat = os.Stat

// Interfaces returns the list of interfaces available for capture.
func (m *Manager) Interfaces() []string {
	return m.cfg.Interfaces
}

// StopAll stops all running capture sessions.
func (m *Manager) StopAll() {
	m.mu.Lock()
	var ids []string
	for id, as := range m.sessions {
		if as.session.State == StateRunning {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()

	for _, id := range ids {
		m.Stop(id)
	}
}
