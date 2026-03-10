package collector

import (
	"testing"
)

func TestRateLimiter_Disabled(t *testing.T) {
	rl := newRateLimiter(0)

	// Should always allow when disabled.
	for i := 0; i < 10000; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("rate limiter should allow everything when limit=0, rejected at iteration %d", i)
		}
	}
}

func TestRateLimiter_Negative(t *testing.T) {
	rl := newRateLimiter(-1)

	for i := 0; i < 100; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatal("negative rate limit should allow everything")
		}
	}
}

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	rl := newRateLimiter(10)

	for i := 0; i < 10; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("should allow up to limit, rejected at iteration %d", i)
		}
	}
}

func TestRateLimiter_RejectsOverLimit(t *testing.T) {
	rl := newRateLimiter(5)

	for i := 0; i < 5; i++ {
		rl.allow("1.2.3.4")
	}

	if rl.allow("1.2.3.4") {
		t.Error("should reject after exceeding limit")
	}
}

func TestRateLimiter_PerSourceIP(t *testing.T) {
	rl := newRateLimiter(3)

	// Fill up quota for 1.2.3.4
	for i := 0; i < 3; i++ {
		rl.allow("1.2.3.4")
	}

	// 5.6.7.8 should still be allowed.
	if !rl.allow("5.6.7.8") {
		t.Error("different source IP should have its own quota")
	}

	// 1.2.3.4 should be rejected.
	if rl.allow("1.2.3.4") {
		t.Error("1.2.3.4 should be rate-limited")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := newRateLimiter(10)

	// Add some entries.
	rl.allow("1.2.3.4")
	rl.allow("5.6.7.8")

	// Cleanup should not panic.
	rl.cleanup()
}

func TestRateLimiter_CleanupDisabled(t *testing.T) {
	rl := newRateLimiter(0)
	// Should not panic.
	rl.cleanup()
}
