package logging

import (
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
	}{
		{"DEBUG", DEBUG},
		{"debug", DEBUG},
		{"INFO", INFO},
		{"info", INFO},
		{"WARN", WARN},
		{"warn", WARN},
		{"ERROR", ERROR},
		{"error", ERROR},
		{"unknown", INFO},
	}
	for _, tt := range tests {
		got := ParseLevel(tt.input)
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARN, "WARN"},
		{ERROR, "ERROR"},
	}
	for _, tt := range tests {
		got := tt.level.String()
		if got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestDefaultLogger(t *testing.T) {
	l := Default()
	if l == nil {
		t.Fatal("Default() returned nil")
	}
	// Should not panic at any level.
	l.Debug("test debug %d", 1)
	l.Info("test info %s", "msg")
	l.Warn("test warn")
	l.Error("test error")
}

func TestSetLevel(t *testing.T) {
	l := Default()
	l.SetLevel(ERROR)
	defer l.SetLevel(INFO) // restore

	// Debug/Info/Warn should be suppressed (no panic expected).
	l.Debug("suppressed")
	l.Info("suppressed")
	l.Warn("suppressed")
	l.Error("visible")
}
