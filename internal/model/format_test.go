package model

import (
	"testing"
	"time"
)

func TestFormatDurationShort(t *testing.T) {
	tests := []struct {
		d        time.Duration
		expected string
	}{
		{500 * time.Millisecond, "500ms"},
		{45 * time.Second, "45s"},
		{5 * time.Minute, "5m"},
		{5*time.Minute + 30*time.Second, "5m 30s"},
		{2 * time.Hour, "2h"},
		{2*time.Hour + 15*time.Minute, "2h 15m"},
		{2*time.Hour + 15*time.Minute + 30*time.Second, "2h 15m"}, // Seconds truncated if h & m > 0
	}

	for _, tt := range tests {
		got := FormatDurationShort(tt.d)
		if got != tt.expected {
			t.Errorf("FormatDurationShort(%v) = %q; want %q", tt.d, got, tt.expected)
		}
	}
}
