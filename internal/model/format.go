package model

import (
	"fmt"
	"time"
)

// FormatDurationShort returns a human-friendly duration string (e.g. "10m" instead of "10m0s").
func FormatDurationShort(d time.Duration) string {
	if d < time.Second {
		return d.String()
	}
	totalSecs := int(d.Seconds())
	h := totalSecs / 3600
	m := (totalSecs % 3600) / 60
	s := totalSecs % 60
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	case m > 0 && s > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
