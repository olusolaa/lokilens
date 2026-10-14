package grafana

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
)

const outputBudget = 24_000

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

func jsonSize(v any) int {
	b, _ := json.Marshal(v)
	return len(b)
}

func joinWarning(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func resolveRange(startIn, endIn string, defaultAgo, maxRange time.Duration) (time.Time, time.Time, string, error) {
	st, err := loki.ParseTimeOrDefault(startIn, defaultAgo)
	if err != nil {
		return st, st, "", err
	}
	et, err := loki.ParseTimeOrDefault(endIn, 0)
	if err != nil {
		return st, et, "", err
	}
	if et.Before(st) {
		st, et = et, st
	}
	if maxRange > 0 && et.Sub(st) > maxRange+time.Minute {
		orig := st
		st = et.Add(-maxRange)
		return st, et, fmt.Sprintf("time range capped to %s (was from %s)", maxRange, orig.Format(time.RFC3339)), nil
	}
	return st, et, "", nil
}
