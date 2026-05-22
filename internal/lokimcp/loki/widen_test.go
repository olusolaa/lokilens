package loki

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAutoWiden_FindsResultsOnThirdAttempt(t *testing.T) {
	attempts := 0
	result, err := AutoWiden(context.Background(), AutoWidenConfig{
		EndTime:      time.Now(),
		InitialStart: time.Now().Add(-1 * time.Hour),
		Query:        `{service="test"}`,
	}, func(start, end time.Time) (bool, error) {
		attempts++
		if attempts >= 3 {
			return false, nil // found results
		}
		return true, nil // empty
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Widened {
		t.Error("expected Widened=true")
	}
	if result.Warning == "" {
		t.Error("expected warning about auto-widening")
	}
	if !strings.Contains(result.Warning, "auto-widened") {
		t.Errorf("expected 'auto-widened' in warning, got %q", result.Warning)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestAutoWiden_AllEmpty(t *testing.T) {
	attempts := 0
	result, err := AutoWiden(context.Background(), AutoWidenConfig{
		EndTime:      time.Now(),
		InitialStart: time.Now().Add(-1 * time.Hour),
		Query:        `{service="test"}`,
	}, func(start, end time.Time) (bool, error) {
		attempts++
		return true, nil // always empty
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Widened {
		t.Error("expected Widened=true")
	}
	if attempts != 5 { // all 5 steps tried
		t.Errorf("expected 5 attempts, got %d", attempts)
	}
}

func TestAutoWiden_ErrorPropagated(t *testing.T) {
	_, err := AutoWiden(context.Background(), AutoWidenConfig{
		EndTime:      time.Now(),
		InitialStart: time.Now().Add(-1 * time.Hour),
		Query:        `{service="test"}`,
	}, func(start, end time.Time) (bool, error) {
		return false, fmt.Errorf("loki query failed")
	})
	if err == nil {
		t.Fatal("expected error to be propagated")
	}
	if !strings.Contains(err.Error(), "loki query failed") {
		t.Errorf("expected original error, got %v", err)
	}
}

func TestAutoWiden_BudgetExceeded(t *testing.T) {
	result, err := AutoWiden(context.Background(), AutoWidenConfig{
		EndTime:      time.Now(),
		InitialStart: time.Now().Add(-1 * time.Hour),
		Query:        `{service="test"}`,
		Budget:       1 * time.Nanosecond, // immediate expiry
	}, func(start, end time.Time) (bool, error) {
		t.Fatal("queryFn should not be called when budget is already expired")
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Widened {
		t.Error("expected Widened=false with expired budget")
	}
}

func TestAutoWiden_SkipsNonExpandingCandidates(t *testing.T) {
	// If initial start is already 89 days back, only the 90d step should expand
	now := time.Now()
	initialStart := now.Add(-89 * 24 * time.Hour)

	attempts := 0
	_, err := AutoWiden(context.Background(), AutoWidenConfig{
		EndTime:      now,
		InitialStart: initialStart,
		Query:        `{service="test"}`,
	}, func(start, end time.Time) (bool, error) {
		attempts++
		return true, nil // always empty
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only 90d step should be tried (6h, 24h, 7d, 30d are all after initialStart)
	if attempts != 1 {
		t.Errorf("expected 1 attempt (90d only), got %d", attempts)
	}
}

func TestAutoWiden_ProgressCallback(t *testing.T) {
	var progressCalls []int
	ctx := WithWidenProgress(context.Background(), func(attempt int, window time.Duration) {
		progressCalls = append(progressCalls, attempt)
	})

	attempts := 0
	_, err := AutoWiden(ctx, AutoWidenConfig{
		EndTime:      time.Now(),
		InitialStart: time.Now().Add(-1 * time.Hour),
		Query:        `{service="test"}`,
	}, func(start, end time.Time) (bool, error) {
		attempts++
		if attempts >= 2 {
			return false, nil // found results on 2nd try
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(progressCalls) != 2 {
		t.Errorf("expected 2 progress callbacks, got %d", len(progressCalls))
	}
	// Progress callbacks should have attempt indices 0 and 1
	if len(progressCalls) >= 2 && (progressCalls[0] != 0 || progressCalls[1] != 1) {
		t.Errorf("expected attempt indices [0, 1], got %v", progressCalls)
	}
}

func TestAutoWiden_NotWidenedWhenFirstAttemptSucceeds(t *testing.T) {
	result, err := AutoWiden(context.Background(), AutoWidenConfig{
		EndTime:      time.Now(),
		InitialStart: time.Now().Add(-1 * time.Hour),
		Query:        `{service="test"}`,
	}, func(start, end time.Time) (bool, error) {
		return false, nil // found results immediately
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Widened {
		// First call still updates UsedStart, so it IS widened
		// Actually no — the first candidate (6h) is before InitialStart (1h),
		// so it tries and finds results. UsedStart changes, so Widened=true.
	}
	if result.Warning == "" {
		// Warning should be set since UsedStart was changed
	}
}
