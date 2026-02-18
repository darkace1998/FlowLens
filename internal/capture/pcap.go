package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// pcapMagic is the PCAP file magic number (little-endian, microsecond resolution).
const pcapMagic = 0xa1b2c3d4

// pcapVersionMajor is the PCAP major version.
const pcapVersionMajor = 2

// pcapVersionMinor is the PCAP minor version.
const pcapVersionMinor = 4

// linkTypeEthernet is the PCAP link-layer type for Ethernet.
const linkTypeEthernet = 1

// PcapWriter writes packets to a PCAP file with optional size-based rotation.
type PcapWriter struct {
	mu        sync.Mutex
	dir       string
	prefix    string
	snapLen   uint32
	maxBytes  int64  // max file size in bytes before rotation (0 = no limit)
	maxFiles  int    // max number of PCAP files to keep (0 = no limit)
	file      *os.File
	written   int64
	pktCount  int64
	startTime time.Time
}

// NewPcapWriter creates a PCAP writer that stores files in dir with the given prefix.
func NewPcapWriter(dir, prefix string, snapLen uint32, maxSizeMB, maxFiles int) (*PcapWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("pcap: create dir: %w", err)
	}

	pw := &PcapWriter{
		dir:      dir,
		prefix:   prefix,
		snapLen:  snapLen,
		maxBytes: int64(maxSizeMB) * 1024 * 1024,
		maxFiles: maxFiles,
	}

	return pw, nil
}

// openNewFile creates a new PCAP file with a timestamp-based name and writes the global header.
func (pw *PcapWriter) openNewFile() error {
	if pw.file != nil {
		pw.file.Close()
	}

	ts := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("%s_%s.pcap", pw.prefix, ts)
	path := filepath.Join(pw.dir, name)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("pcap: create file: %w", err)
	}

	// Write PCAP global header (24 bytes).
	if err := pw.writeGlobalHeader(f); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}

	pw.file = f
	pw.written = 24 // global header size
	pw.startTime = time.Now()
	return nil
}

// writeGlobalHeader writes the 24-byte PCAP global header.
func (pw *PcapWriter) writeGlobalHeader(w io.Writer) error {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], pcapVersionMajor)
	binary.LittleEndian.PutUint16(hdr[6:8], pcapVersionMinor)
	// thiszone, sigfigs = 0
	binary.LittleEndian.PutUint32(hdr[16:20], pw.snapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], linkTypeEthernet)
	_, err := w.Write(hdr)
	return err
}

// WritePacket writes a single packet record to the PCAP file.
// It handles file rotation when maxBytes is exceeded.
func (pw *PcapWriter) WritePacket(data []byte, ts time.Time) error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.file == nil {
		if err := pw.openNewFile(); err != nil {
			return err
		}
	}

	// Rotate if the file exceeds the max size.
	recLen := 16 + len(data)
	if pw.maxBytes > 0 && pw.written+int64(recLen) > pw.maxBytes {
		if err := pw.openNewFile(); err != nil {
			return err
		}
		pw.pruneOldFiles()
	}

	// Truncate to snapLen.
	capturedLen := len(data)
	if uint32(capturedLen) > pw.snapLen {
		capturedLen = int(pw.snapLen)
	}

	// Write PCAP packet record header (16 bytes).
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(ts.Nanosecond()/1000)) // microseconds
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(capturedLen))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(data)))

	if _, err := pw.file.Write(hdr); err != nil {
		return fmt.Errorf("pcap: write pkt header: %w", err)
	}
	if _, err := pw.file.Write(data[:capturedLen]); err != nil {
		return fmt.Errorf("pcap: write pkt data: %w", err)
	}

	pw.written += int64(16 + capturedLen)
	pw.pktCount++
	return nil
}

// Close closes the current PCAP file.
func (pw *PcapWriter) Close() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.file != nil {
		err := pw.file.Close()
		pw.file = nil
		return err
	}
	return nil
}

// Stats returns the number of packets written and the current file size.
func (pw *PcapWriter) Stats() (packets int64, bytes int64) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return pw.pktCount, pw.written
}

// pruneOldFiles removes old PCAP files if maxFiles is exceeded.
func (pw *PcapWriter) pruneOldFiles() {
	if pw.maxFiles <= 0 {
		return
	}

	files, err := filepath.Glob(filepath.Join(pw.dir, pw.prefix+"_*.pcap"))
	if err != nil {
		return
	}

	if len(files) <= pw.maxFiles {
		return
	}

	// Sort by name (timestamp-based) ascending — oldest first.
	sort.Strings(files)

	// Remove excess files (oldest).
	toRemove := len(files) - pw.maxFiles
	for i := 0; i < toRemove; i++ {
		os.Remove(files[i])
	}
}

// ListPcapFiles returns a list of PCAP files in the capture directory.
func ListPcapFiles(dir string) ([]PcapFileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var files []PcapFileInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pcap") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, PcapFileInfo{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	// Sort by modification time descending — newest first.
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.After(files[j].ModTime)
	})

	return files, nil
}

// PcapFileInfo describes a PCAP file on disk.
type PcapFileInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
}
