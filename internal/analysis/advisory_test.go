package analysis

import (
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		expected string
	}{
		{
			name:     "INFO severity",
			severity: INFO,
			expected: "INFO",
		},
		{
			name:     "WARNING severity",
			severity: WARNING,
			expected: "WARNING",
		},
		{
			name:     "CRITICAL severity",
			severity: CRITICAL,
			expected: "CRITICAL",
		},
		{
			name:     "Unknown severity",
			severity: Severity(99),
			expected: "Severity(99)",
		},
		{
			name:     "Negative severity",
			severity: Severity(-1),
			expected: "Severity(-1)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.severity.String()
			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}
