package prometheus

import (
	"fmt"
	"math"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
)

// Validator enforces query safety for the metrics backend: it bounds the
// number of points a range query can request and caps the time range.
type Validator struct {
	maxPoints int
	maxRange  time.Duration
}

func NewValidator(maxPoints int, maxRange time.Duration) *Validator {
	if maxPoints <= 0 {
		maxPoints = 11000
	}
	if maxRange <= 0 {
		maxRange = 30 * 24 * time.Hour
	}
	return &Validator{maxPoints: maxPoints, maxRange: maxRange}
}

// CapRange enforces maxRange. Returns adjusted start and a warning (empty if none).
func (v *Validator) CapRange(start, end time.Time) (time.Time, time.Time, string) {
	if end.Before(start) {
		start, end = end, start
	}
	if end.Sub(start) > v.maxRange {
		orig := start
		start = end.Add(-v.maxRange)
		return start, end, fmt.Sprintf("time range capped to %s (was from %s)", v.maxRange, orig.Format(time.RFC3339))
	}
	return start, end, ""
}

// ResolveStep returns a step that keeps the point count within maxPoints.
// If requestedStep is empty, it starts from loki.AutoSelectStep, then widens.
func (v *Validator) ResolveStep(start, end time.Time, requestedStep string) string {
	step := requestedStep
	if step == "" {
		step = loki.AutoSelectStep(start, end)
	}
	rangeSecs := end.Sub(start).Seconds()
	if rangeSecs <= 0 {
		return step
	}
	stepSecs := parseStepSeconds(step)
	if stepSecs <= 0 {
		stepSecs = 60
	}
	// Minimum step (seconds) that keeps points <= maxPoints.
	minStep := int64(math.Ceil(rangeSecs / float64(v.maxPoints)))
	if int64(stepSecs) >= minStep {
		return step // requested step is already coarse enough
	}
	return fmt.Sprintf("%ds", minStep)
}

// parseStepSeconds parses a Prometheus step ("30s", "1m", "1h") to seconds.
// Returns 0 if unparseable.
func parseStepSeconds(step string) float64 {
	d, err := time.ParseDuration(step)
	if err != nil {
		return 0
	}
	return d.Seconds()
}
