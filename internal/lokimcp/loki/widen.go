package loki

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// DefaultWidenSteps is the progression of time windows tried during auto-widening.
var DefaultWidenSteps = []time.Duration{
	6 * time.Hour,
	24 * time.Hour,
	7 * 24 * time.Hour,
	30 * 24 * time.Hour,
	90 * 24 * time.Hour,
}

// DefaultWidenBudget is the maximum wall-clock time to spend auto-widening
// before returning whatever we have. Leaves room for the LLM to process results
// within the agent timeout.
const DefaultWidenBudget = 90 * time.Second

// AutoWidenConfig configures the auto-widen behavior.
type AutoWidenConfig struct {
	EndTime      time.Time
	InitialStart time.Time
	Query        string        // for logging
	Budget       time.Duration // 0 = DefaultWidenBudget
	MaxRange     time.Duration // 0 = no limit; skip steps that exceed this
}

// AutoWidenResult captures what happened during auto-widening.
type AutoWidenResult struct {
	UsedStart time.Time
	Widened   bool
	Warning   string
}

type widenProgressKey struct{}

// WithWidenProgress attaches a widen progress callback to the context.
// The callback receives the 0-based attempt index and the time window being tried.
// Tool handlers pass this context through to AutoWiden, which calls the callback
// on each expansion step — enabling streaming progress updates in Slack.
func WithWidenProgress(ctx context.Context, fn func(attempt int, window time.Duration)) context.Context {
	return context.WithValue(ctx, widenProgressKey{}, fn)
}

// AutoWiden progressively expands a query's time range when results are empty.
// The queryFn callback executes the query for [start, end) and returns true if
// the result is empty. Only call this when the initial query returned empty AND
// no explicit start time was given.
func AutoWiden(ctx context.Context, cfg AutoWidenConfig, queryFn func(start, end time.Time) (isEmpty bool, err error)) (AutoWidenResult, error) {
	result := AutoWidenResult{UsedStart: cfg.InitialStart}

	budget := cfg.Budget
	if budget == 0 {
		budget = DefaultWidenBudget
	}
	// Sub-millisecond budgets are effectively zero — skip widening entirely.
	// This also prevents flaky timing in tests.
	if budget < time.Millisecond {
		return result, nil
	}

	onWiden, _ := ctx.Value(widenProgressKey{}).(func(int, time.Duration))
	loopStart := time.Now()

	for i, widen := range DefaultWidenSteps {
		if time.Since(loopStart) > budget {
			slog.Warn("auto-widen timeout budget exceeded, stopping",
				slog.Duration("elapsed", time.Since(loopStart)),
				slog.String("query", cfg.Query))
			break
		}

		// Skip steps that exceed the backend's max query range (e.g. Loki's 30d limit).
		if cfg.MaxRange > 0 && widen > cfg.MaxRange {
			continue
		}

		candidate := cfg.EndTime.Add(-widen)
		if !candidate.Before(result.UsedStart) {
			continue
		}
		result.UsedStart = candidate

		if onWiden != nil {
			onWiden(i, widen)
		}

		isEmpty, err := queryFn(result.UsedStart, cfg.EndTime)
		if err != nil {
			return result, err
		}
		if !isEmpty {
			break
		}
	}

	if result.UsedStart.Before(cfg.InitialStart) {
		result.Widened = true
		result.Warning = fmt.Sprintf("auto-widened from %s to %s (no results in default 1h window)",
			result.UsedStart.Format(time.RFC3339), cfg.EndTime.Format(time.RFC3339))
	}

	return result, nil
}
