package loki

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Shared output types used by all log source plugins.

type LogEntry struct {
	Timestamp string            `json:"timestamp"`
	Line      string            `json:"line"`
	Labels    map[string]string `json:"labels"`
}

type ErrorPattern struct {
	Pattern string  `json:"pattern"`
	Count   int     `json:"count"`
	Pct     float64 `json:"pct"`
	Sample  string  `json:"sample"`
}

type QueryLogsOutput struct {
	Logs          []LogEntry                `json:"logs"`
	TotalLogs     int                       `json:"total_logs"`
	Truncated     bool                      `json:"truncated"`
	Direction     string                    `json:"direction"`
	Query         string                    `json:"query_executed"`
	TimeRange     string                    `json:"time_range"`
	Warning       string                    `json:"warning,omitempty"`
	ExecTimeMS    int                       `json:"exec_time_ms,omitempty"`
	TopPatterns   []ErrorPattern            `json:"top_patterns,omitempty"`
	TotalPatterns int                       `json:"total_patterns,omitempty"`
	UniqueLabels  map[string]map[string]int `json:"unique_labels,omitempty"`
}

type DataPoint struct {
	Timestamp string `json:"timestamp"`
	Value     string `json:"value"`
}

type MetricSeries struct {
	Labels map[string]string `json:"labels"`
	Values []DataPoint       `json:"values"`
}

type TrendSummary struct {
	Total        float64 `json:"total"`
	Avg          float64 `json:"avg"`
	AvgPerMinute float64 `json:"avg_per_minute"`
	Latest       float64 `json:"latest"`
	Peak         float64 `json:"peak"`
	PeakTime     string  `json:"peak_time,omitempty"`
	Trend        string  `json:"trend"`
	NonZeroPct   float64 `json:"non_zero_pct"`
}

type QueryStatsOutput struct {
	Series      []MetricSeries          `json:"series"`
	TotalSeries int                     `json:"total_series"`
	Step        string                  `json:"step,omitempty"`
	Query       string                  `json:"query_executed"`
	TimeRange   string                  `json:"time_range,omitempty"`
	Warning     string                  `json:"warning,omitempty"`
	ExecTimeMS  int                     `json:"exec_time_ms,omitempty"`
	Summaries   map[string]TrendSummary `json:"summaries,omitempty"`
}

// maxLogLineLength caps individual log lines sent to the LLM.
const maxLogLineLength = 1500

// maxDataPointsPerSeries caps the raw data points sent to the LLM per series.
const maxDataPointsPerSeries = 24

// maxSampleLogs is the number of representative log lines kept after analysis.
// The model uses patterns and summaries for reasoning — raw lines are only
// needed for evidence quotes (2-3 lines) and extracting identifiers for
// follow-up queries. 5 samples is enough for both.
const maxSampleLogs = 5

// AnalyzeLogs enriches a QueryLogsOutput with pattern analysis, label distribution,
// and log sorting, then compacts the raw logs to a small sample. The model gets
// the full analysis (patterns, distributions, counts) plus a few representative
// lines for evidence — not the full bulk.
func AnalyzeLogs(out *QueryLogsOutput, limit int) {
	out.TotalLogs = len(out.Logs)
	out.Truncated = out.TotalLogs >= limit

	if out.Direction == "forward" {
		sort.Slice(out.Logs, func(i, j int) bool {
			return out.Logs[i].Timestamp < out.Logs[j].Timestamp
		})
	} else {
		sort.Slice(out.Logs, func(i, j int) bool {
			return out.Logs[i].Timestamp > out.Logs[j].Timestamp
		})
	}

	if out.TotalLogs >= 3 {
		var totalPatterns int
		out.TopPatterns, totalPatterns = extractPatterns(out.Logs, 10)
		if totalPatterns > len(out.TopPatterns) {
			out.TotalPatterns = totalPatterns
		}
	}

	out.UniqueLabels = make(map[string]map[string]int)
	labelNames := collectLabelNames(out.Logs)
	for _, label := range labelNames {
		if dist := extractLabelDistribution(out.Logs, label); dist != nil {
			out.UniqueLabels[label] = dist
		}
	}
	if len(out.UniqueLabels) == 0 {
		out.UniqueLabels = nil
	}

	// Compact: keep only a sample of raw logs. The analysis (patterns,
	// distributions, counts) is already extracted — the model only needs
	// a few lines for evidence in its response.
	if len(out.Logs) > maxSampleLogs {
		out.Logs = out.Logs[:maxSampleLogs]
	}
}

// maxSampleSeries is the number of series to keep raw data points for.
// The model has summaries (trend, peak, avg) for ALL series — raw data points
// are only needed for a few series to support detailed follow-ups.
const maxSampleSeries = 5

// AnalyzeStats enriches a QueryStatsOutput with trend summaries and downsampling,
// then compacts the series data. Summaries are kept for all series (they're small).
// Raw data points are kept only for the top few series.
func AnalyzeStats(out *QueryStatsOutput) {
	out.TotalSeries = len(out.Series)

	if len(out.Series) > 0 {
		stepMinutes := stepToMinutes(out.Step)
		out.Summaries = make(map[string]TrendSummary, len(out.Series))
		for i, s := range out.Series {
			key := seriesKey(s.Labels)
			summary := computeTrend(s.Values)
			if stepMinutes > 0 {
				summary.AvgPerMinute = math.Round(summary.Avg/stepMinutes*100) / 100
			}
			out.Summaries[key] = summary
			out.Series[i].Values = downsampleDataPoints(s.Values, maxDataPointsPerSeries)
		}

		// Compact: keep raw data points only for top series. The model has
		// summaries for all series — raw points are only needed for evidence.
		if len(out.Series) > maxSampleSeries {
			for i := maxSampleSeries; i < len(out.Series); i++ {
				out.Series[i].Values = nil
			}
		}
	}
}

// TruncateLogLine truncates a log line to maxLogLineLength if needed,
// preserving UTF-8 rune boundaries.
func TruncateLogLine(line string) string {
	if len(line) > maxLogLineLength {
		return truncateRuneSafe(line, maxLogLineLength) + "…[truncated]"
	}
	return line
}

// AutoSelectStep picks a reasonable query step based on the time range.
func AutoSelectStep(start, end time.Time) string {
	return autoSelectStep(start, end)
}

// ParseTimeOrDefault parses a relative time string or returns a default.
func ParseTimeOrDefault(input string, defaultAgo time.Duration) (time.Time, error) {
	if input == "" {
		if defaultAgo == 0 {
			return time.Now(), nil
		}
		return time.Now().Add(-defaultAgo), nil
	}
	return ParseRelativeTime(input)
}

// --- Internal helpers ---

func stepToMinutes(step string) float64 {
	d, err := time.ParseDuration(step)
	if err != nil {
		return 0
	}
	return d.Minutes()
}

func autoSelectStep(start, end time.Time) string {
	dur := end.Sub(start)
	switch {
	case dur <= 30*time.Minute:
		return "30s"
	case dur <= 2*time.Hour:
		return "1m"
	case dur <= 6*time.Hour:
		return "5m"
	case dur <= 12*time.Hour:
		return "15m"
	default:
		return "1h"
	}
}

func parseTimeOrDefault(input string, defaultAgo time.Duration) (time.Time, error) {
	if input == "" {
		if defaultAgo == 0 {
			return time.Now(), nil
		}
		return time.Now().Add(-defaultAgo), nil
	}
	return ParseRelativeTime(input)
}

func downsampleDataPoints(values []DataPoint, maxPoints int) []DataPoint {
	if len(values) <= maxPoints {
		return values
	}
	result := make([]DataPoint, 0, maxPoints)
	result = append(result, values[0])

	step := float64(len(values)-1) / float64(maxPoints-1)
	for i := 1; i < maxPoints-1; i++ {
		idx := int(math.Round(float64(i) * step))
		result = append(result, values[idx])
	}

	result = append(result, values[len(values)-1])
	return result
}

var patternNormalizer = regexp.MustCompile(
	`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b` +
		`|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b` +
		`|\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*\b` +
		`|\b0x[0-9a-f]+\b` +
		`|\b\d{5,}\b`,
)

func extractPatterns(logs []LogEntry, topN int) ([]ErrorPattern, int) {
	if len(logs) == 0 {
		return nil, 0
	}

	type patternData struct {
		count  int
		sample string
	}
	groups := make(map[string]*patternData)

	for _, entry := range logs {
		line := extractLogMessage(entry.Line)
		sig := patternNormalizer.ReplaceAllString(line, "<*>")
		sig = strings.ReplaceAll(sig, "<*>:<*>", "<*>")
		if len(sig) > 200 {
			sig = truncateRuneSafe(sig, 200) + "..."
		}
		if g, ok := groups[sig]; ok {
			g.count++
		} else {
			groups[sig] = &patternData{count: 1, sample: line}
		}
	}

	total := len(logs)
	patterns := make([]ErrorPattern, 0, len(groups))
	for sig, g := range groups {
		sample := g.sample
		if len(sample) > 200 {
			sample = truncateRuneSafe(sample, 200) + "..."
		}
		patterns = append(patterns, ErrorPattern{
			Pattern: sig,
			Count:   g.count,
			Pct:     math.Round(float64(g.count)/float64(total)*1000) / 10,
			Sample:  sample,
		})
	}

	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].Count > patterns[j].Count
	})

	totalPatterns := len(patterns)
	if len(patterns) > topN {
		patterns = patterns[:topN]
	}
	return patterns, totalPatterns
}

// maxLabelValues caps the number of unique values per label in the distribution.
// High-cardinality labels (trace_id, request_id) can have thousands of unique
// values, bloating the tool result sent to the LLM. We keep the top N by
// frequency — the LLM cares about which values are common, not every unique ID.
const maxLabelValues = 15

func extractLabelDistribution(logs []LogEntry, label string) map[string]int {
	if len(logs) == 0 {
		return nil
	}
	dist := make(map[string]int)
	for _, entry := range logs {
		if v, ok := entry.Labels[label]; ok {
			dist[v]++
		}
	}
	if len(dist) <= 1 {
		return nil
	}

	// Cap high-cardinality labels to top N by frequency
	if len(dist) > maxLabelValues {
		type kv struct {
			key   string
			count int
		}
		sorted := make([]kv, 0, len(dist))
		for k, v := range dist {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		capped := make(map[string]int, maxLabelValues+1)
		for i := 0; i < maxLabelValues && i < len(sorted); i++ {
			capped[sorted[i].key] = sorted[i].count
		}
		// Add a sentinel so the LLM knows the list was truncated
		omitted := len(dist) - maxLabelValues
		capped[fmt.Sprintf("... and %d more unique values", omitted)] = 0
		return capped
	}

	return dist
}

// safeParseFloat parses a string as float64, returning 0 and false for
// unparseable values, NaN, and Inf.
func safeParseFloat(s string) (float64, bool) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

func computeTrend(values []DataPoint) TrendSummary {
	if len(values) == 0 {
		return TrendSummary{Trend: "sparse"}
	}

	var total, peak, latest float64
	var peakTime string
	nonZero := 0
	validCount := 0

	for _, dp := range values {
		v, ok := safeParseFloat(dp.Value)
		if !ok {
			continue
		}
		validCount++
		total += v
		latest = v
		if v > peak {
			peak = v
			peakTime = dp.Timestamp
		}
		if v > 0 {
			nonZero++
		}
	}

	if validCount == 0 {
		return TrendSummary{Trend: "sparse"}
	}

	nonZeroPct := float64(nonZero) / float64(validCount) * 100
	avg := total / float64(validCount)

	trend := "stable"
	if validCount < 3 {
		if total == 0 {
			trend = "sparse"
		}
	} else {
		third := len(values) / 3
		var firstSum, lastSum float64
		for i := 0; i < third; i++ {
			if v, ok := safeParseFloat(values[i].Value); ok {
				firstSum += v
			}
		}
		for i := len(values) - third; i < len(values); i++ {
			if v, ok := safeParseFloat(values[i].Value); ok {
				lastSum += v
			}
		}
		if firstSum == 0 && lastSum == 0 {
			trend = "sparse"
		} else if firstSum == 0 {
			if lastSum > 0 {
				trend = "increasing"
			}
		} else if lastSum > firstSum*1.3 {
			trend = "increasing"
		} else if lastSum < firstSum*0.7 {
			trend = "decreasing"
		}
	}

	return TrendSummary{
		Total:      math.Round(total*100) / 100,
		Avg:        math.Round(avg*100) / 100,
		Latest:     math.Round(latest*100) / 100,
		Peak:       math.Round(peak*100) / 100,
		PeakTime:   peakTime,
		Trend:      trend,
		NonZeroPct: math.Round(nonZeroPct*10) / 10,
	}
}

func extractLogMessage(line string) string {
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return line
	}

	if line[0] == '{' {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			return line
		}
		for _, key := range []string{"msg", "message", "error", "err", "log", "error_message", "reason", "detail"} {
			if v, ok := parsed[key]; ok {
				if s, ok := v.(string); ok && s != "" {
					return strings.TrimRight(s, "\n\r")
				}
			}
		}
		for _, key := range []string{"error", "err"} {
			if v, ok := parsed[key]; ok {
				if m, ok := v.(map[string]any); ok {
					for _, msgKey := range []string{"message", "msg"} {
						if inner, ok := m[msgKey]; ok {
							if s, ok := inner.(string); ok && s != "" {
								return s
							}
						}
					}
				}
			}
		}
		return line
	}

	for _, key := range []string{"msg=", "message=", "error=", "err=", "error_message=", "reason=", "detail="} {
		if msg := extractLogfmtValue(line, key); msg != "" {
			return msg
		}
	}

	return line
}

func extractLogfmtValue(line, key string) string {
	searchFrom := 0
	for searchFrom < len(line) {
		idx := strings.Index(line[searchFrom:], key)
		if idx == -1 {
			return ""
		}
		idx += searchFrom
		if idx > 0 && line[idx-1] != ' ' && line[idx-1] != '\t' {
			searchFrom = idx + len(key)
			continue
		}
		val := line[idx+len(key):]
		if len(val) == 0 {
			return ""
		}
		if val[0] == '"' {
			end := strings.IndexByte(val[1:], '"')
			if end >= 0 {
				return val[1 : end+1]
			}
			return val[1:]
		}
		end := strings.IndexByte(val, ' ')
		if end == -1 {
			return val
		}
		return val[:end]
	}
	return ""
}

// collectLabelNames returns all distinct label names present in the log entries.
// Skips internal labels (prefixed with "__").
func collectLabelNames(logs []LogEntry) []string {
	seen := make(map[string]struct{})
	for _, entry := range logs {
		for k := range entry.Labels {
			if strings.HasPrefix(k, "__") {
				continue
			}
			seen[k] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for k := range seen {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func truncateRuneSafe(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

func seriesKey(labels map[string]string) string {
	if len(labels) == 0 {
		return "total"
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
