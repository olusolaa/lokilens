package loki

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var relativeTimePattern = regexp.MustCompile(`^(\d+)\s*(s|sec|second|seconds|m|min|minute|minutes|h|hour|hours|d|day|days|w|week|weeks)\s*(ago)?$`)

// lastNPattern matches "last N hours", "last 30 minutes", "last 3 days", etc.
var lastNPattern = regexp.MustCompile(`^last\s+(\d+)\s*(s|sec|second|seconds|m|min|minute|minutes|h|hour|hours|d|day|days|w|week|weeks)$`)

// ParseRelativeTime parses time strings in various formats:
// - "now" → current time
// - "2h ago", "30m ago", "1d ago" → relative to now
// - "2h", "30m" → also treated as relative (ago implied)
// - "yesterday", "last night", "last 2 hours" → natural language
// - "yesterday at noon", "yesterday at 2pm" → natural language with time of day
// - RFC3339 → parsed directly
// - Unix nanosecond timestamp → parsed as integer
func ParseRelativeTime(input string) (time.Time, error) {
	input = strings.TrimSpace(input)

	if input == "" || strings.EqualFold(input, "now") {
		return time.Now(), nil
	}

	// Try relative time: "2h ago", "30m", "1d ago" (case-insensitive)
	lower := strings.ToLower(input)
	if matches := relativeTimePattern.FindStringSubmatch(lower); matches != nil {
		amount, _ := strconv.Atoi(matches[1])
		unit := matches[2]
		dur := toDuration(amount, unit)
		return time.Now().Add(-dur), nil
	}

	// Natural language: "yesterday", "last night", "last 2 hours", etc.
	if t, ok := parseNaturalTime(lower); ok {
		return t, nil
	}

	// Try Go duration format: "2h30m", "45s"
	if d, err := time.ParseDuration(lower); err == nil {
		return time.Now().Add(-d), nil
	}

	// Try RFC3339 (normalize lowercase t/z that LLMs sometimes generate,
	// e.g. "2026-03-10t17:02:09z" instead of "2026-03-10T17:02:09Z")
	normalized := normalizeRFC3339Case(input)
	if t, err := time.Parse(time.RFC3339, normalized); err == nil {
		return t, nil
	}

	// Try RFC3339Nano
	if t, err := time.Parse(time.RFC3339Nano, normalized); err == nil {
		return t, nil
	}

	// Try Unix nanosecond timestamp
	if ns, err := strconv.ParseInt(input, 10, 64); err == nil {
		return time.Unix(0, ns), nil
	}

	return time.Time{}, fmt.Errorf("cannot parse time %q: expected relative (e.g., '2h ago', 'yesterday', 'last 2 hours'), RFC3339, or Unix nanoseconds", input)
}

// parseNaturalTime handles natural language time expressions the LLM might
// generate even though the instruction asks for relative format.
func parseNaturalTime(lower string) (time.Time, bool) {
	now := time.Now()

	switch lower {
	case "yesterday":
		return now.Add(-24 * time.Hour), true
	case "today":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()), true
	case "this morning":
		morning := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, now.Location())
		if morning.After(now) {
			morning = morning.Add(-24 * time.Hour)
		}
		return morning, true
	case "last night":
		return now.Add(-12 * time.Hour), true
	case "last week":
		return now.Add(-7 * 24 * time.Hour), true
	case "last month":
		return now.AddDate(0, -1, 0), true
	case "noon", "today at noon", "at noon":
		return time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, now.Location()), true
	case "midnight", "today at midnight", "at midnight":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()), true
	case "yesterday at noon":
		y := now.AddDate(0, 0, -1)
		return time.Date(y.Year(), y.Month(), y.Day(), 12, 0, 0, 0, now.Location()), true
	case "yesterday at midnight":
		y := now.AddDate(0, 0, -1)
		return time.Date(y.Year(), y.Month(), y.Day(), 0, 0, 0, 0, now.Location()), true
	}

	// "last N hours/minutes/days"
	if matches := lastNPattern.FindStringSubmatch(lower); matches != nil {
		amount, _ := strconv.Atoi(matches[1])
		dur := toDuration(amount, matches[2])
		return now.Add(-dur), true
	}

	// "yesterday at <time>" → yesterday at specific time
	if strings.HasPrefix(lower, "yesterday at ") {
		if tod, ok := parseTimeOfDayStr(lower[len("yesterday at "):]); ok {
			y := now.AddDate(0, 0, -1)
			return time.Date(y.Year(), y.Month(), y.Day(), tod.hour, tod.min, 0, 0, now.Location()), true
		}
	}

	return time.Time{}, false
}

type parsedTOD struct {
	hour, min int
}

// parseTimeOfDayStr parses "2pm", "2:30pm", "14:00", "noon", "midnight".
func parseTimeOfDayStr(s string) (parsedTOD, bool) {
	s = strings.TrimSpace(s)

	switch s {
	case "noon":
		return parsedTOD{12, 0}, true
	case "midnight":
		return parsedTOD{0, 0}, true
	}

	// Match "2pm", "2:30pm", "14:00"
	pattern := regexp.MustCompile(`^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$`)
	matches := pattern.FindStringSubmatch(s)
	if matches == nil {
		return parsedTOD{}, false
	}

	hour, _ := strconv.Atoi(matches[1])
	minute := 0
	if matches[2] != "" {
		minute, _ = strconv.Atoi(matches[2])
	}

	if matches[3] == "pm" && hour < 12 {
		hour += 12
	} else if matches[3] == "am" && hour == 12 {
		hour = 0
	}

	if hour > 23 || minute > 59 {
		return parsedTOD{}, false
	}

	return parsedTOD{hour, minute}, true
}

// normalizeRFC3339Case fixes lowercase 't' and 'z' in RFC3339 timestamps
// that LLMs sometimes generate (e.g. "2026-03-10t17:02:09z").
func normalizeRFC3339Case(s string) string {
	if len(s) < 20 {
		return s
	}
	if s[10] != 't' && s[10] != 'T' {
		return s
	}
	buf := []byte(s)
	buf[10] = 'T'
	if buf[len(buf)-1] == 'z' {
		buf[len(buf)-1] = 'Z'
	}
	return string(buf)
}

func toDuration(amount int, unit string) time.Duration {
	switch unit {
	case "s", "sec", "second", "seconds":
		return time.Duration(amount) * time.Second
	case "m", "min", "minute", "minutes":
		return time.Duration(amount) * time.Minute
	case "h", "hour", "hours":
		return time.Duration(amount) * time.Hour
	case "d", "day", "days":
		return time.Duration(amount) * 24 * time.Hour
	case "w", "week", "weeks":
		return time.Duration(amount) * 7 * 24 * time.Hour
	default:
		return time.Duration(amount) * time.Hour
	}
}

// FormatNano formats a time.Time as nanosecond Unix epoch string for Loki API.
func FormatNano(t time.Time) string {
	return strconv.FormatInt(t.UnixNano(), 10)
}

// ParseNanoTimestamp parses a nanosecond Unix epoch string into time.Time.
func ParseNanoTimestamp(ns string) (time.Time, error) {
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid nanosecond timestamp %q: %w", ns, err)
	}
	return time.Unix(0, n), nil
}

// Clamp constrains a value between min and max.
func Clamp(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}
