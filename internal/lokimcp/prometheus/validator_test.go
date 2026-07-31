package prometheus

import (
	"testing"
	"time"
)

func TestResolveStep_WidensWhenTooManyPoints(t *testing.T) {
	v := NewValidator(11000, 30*24*time.Hour)
	start := time.Unix(0, 0)
	end := time.Unix(7*24*3600, 0) // 7 days = 604800s
	// requested 1s step → 604800 points, way over 11000. Must widen.
	step := v.ResolveStep(start, end, "1s")
	if step == "1s" {
		t.Fatal("expected step to widen beyond 1s")
	}
	// resulting step must keep points <= 11000
	secs := durationStringToSeconds(t, step)
	if pts := int64(604800) / secs; pts > 11000 {
		t.Fatalf("step %s yields %d points (> 11000)", step, pts)
	}
}

func TestResolveStep_KeepsReasonableStep(t *testing.T) {
	v := NewValidator(11000, 30*24*time.Hour)
	start := time.Unix(0, 0)
	end := time.Unix(3600, 0) // 1h
	step := v.ResolveStep(start, end, "1m") // 60 points — fine
	if step != "1m" {
		t.Fatalf("step = %q, want 1m", step)
	}
}

func TestCapRange_EnforcesMax(t *testing.T) {
	v := NewValidator(11000, 24*time.Hour)
	end := time.Now()
	start := end.Add(-72 * time.Hour) // 3 days, over the 24h cap
	gotStart, _, warn := v.CapRange(start, end)
	if end.Sub(gotStart) > 24*time.Hour+time.Second {
		t.Fatalf("range not capped: %v", end.Sub(gotStart))
	}
	if warn == "" {
		t.Fatal("expected a warning when capping range")
	}
}

func durationStringToSeconds(t *testing.T, s string) int64 {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("bad duration %q: %v", s, err)
	}
	return int64(d.Seconds())
}
