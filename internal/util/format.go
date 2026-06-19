package util

import "fmt"

// FormatBytes converts a byte count into a human-readable short string (e.g. "1.5 MB").
func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatCount converts a packet count into a human-readable short string (e.g. "1.5K").
func FormatCount(p uint64) string {
	switch {
	case p < 1000:
		return fmt.Sprintf("%d", p)
	case p < 1_000_000:
		return fmt.Sprintf("%.1fK", float64(p)/1e3)
	case p < 1_000_000_000:
		return fmt.Sprintf("%.1fM", float64(p)/1e6)
	case p < 1_000_000_000_000:
		return fmt.Sprintf("%.1fB", float64(p)/1e9)
	default:
		return fmt.Sprintf("%.1fT", float64(p)/1e12)
	}
}
