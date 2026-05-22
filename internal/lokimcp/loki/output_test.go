package loki

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Existing tests (preserved from original file)
// ---------------------------------------------------------------------------

func TestExtractPatterns_GroupsSimilarLines(t *testing.T) {
	logs := []LogEntry{
		{Line: "connection timeout to 10.0.1.5:5432 after 30000ms"},
		{Line: "connection timeout to 10.0.1.6:5432 after 30000ms"},
		{Line: "connection timeout to 10.0.1.7:5432 after 30000ms"},
		{Line: "null pointer exception in OrderService.process(OrderService.java:142)"},
		{Line: "null pointer exception in OrderService.process(OrderService.java:142)"},
		{Line: "rate limit exceeded for user abc123"},
	}
	patterns, totalPatterns := extractPatterns(logs, 5)
	if len(patterns) == 0 {
		t.Fatal("expected patterns, got none")
	}
	if patterns[0].Count != 3 {
		t.Errorf("expected top pattern count=3, got %d", patterns[0].Count)
	}
	if len(patterns) != 3 {
		t.Errorf("expected 3 patterns, got %d", len(patterns))
	}
	if patterns[0].Pct != 50.0 {
		t.Errorf("expected top pattern pct=50.0, got %f", patterns[0].Pct)
	}
	if totalPatterns != 3 {
		t.Errorf("expected totalPatterns=3, got %d", totalPatterns)
	}
}

func TestExtractPatterns_TopNLimit(t *testing.T) {
	logs := make([]LogEntry, 0)
	for i := 0; i < 20; i++ {
		logs = append(logs, LogEntry{Line: "unique error " + string(rune('A'+i))})
	}
	patterns, totalPatterns := extractPatterns(logs, 5)
	if len(patterns) > 5 {
		t.Errorf("expected at most 5 patterns, got %d", len(patterns))
	}
	if totalPatterns != 20 {
		t.Errorf("expected totalPatterns=20, got %d", totalPatterns)
	}
}

func TestExtractPatterns_NormalizesUUIDs(t *testing.T) {
	logs := []LogEntry{
		{Line: "failed to process order 550e8400-e29b-41d4-a716-446655440000"},
		{Line: "failed to process order a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
	}
	patterns, _ := extractPatterns(logs, 5)
	if len(patterns) != 1 {
		t.Errorf("expected 1 pattern after UUID normalization, got %d", len(patterns))
	}
	if patterns[0].Count != 2 {
		t.Errorf("expected count=2, got %d", patterns[0].Count)
	}
}

func TestExtractPatterns_NormalizesIPs(t *testing.T) {
	logs := []LogEntry{
		{Line: "connection refused from 192.168.1.100:8080"},
		{Line: "connection refused from 10.0.0.5:8080"},
	}
	patterns, _ := extractPatterns(logs, 5)
	if len(patterns) != 1 {
		t.Errorf("expected 1 pattern after IP normalization, got %d", len(patterns))
	}
}

func TestExtractLabelDistribution(t *testing.T) {
	logs := []LogEntry{
		{Labels: map[string]string{"service": "payments"}},
		{Labels: map[string]string{"service": "payments"}},
		{Labels: map[string]string{"service": "orders"}},
	}
	dist := extractLabelDistribution(logs, "service")
	if dist == nil {
		t.Fatal("expected distribution, got nil")
	}
	if dist["payments"] != 2 {
		t.Errorf("expected payments=2, got %d", dist["payments"])
	}
	if dist["orders"] != 1 {
		t.Errorf("expected orders=1, got %d", dist["orders"])
	}
}

func TestExtractLabelDistribution_SingleValue(t *testing.T) {
	logs := []LogEntry{
		{Labels: map[string]string{"service": "payments"}},
		{Labels: map[string]string{"service": "payments"}},
	}
	dist := extractLabelDistribution(logs, "service")
	if dist != nil {
		t.Errorf("expected nil for single-value distribution, got %v", dist)
	}
}

func TestExtractLabelDistribution_Empty(t *testing.T) {
	dist := extractLabelDistribution(nil, "service")
	if dist != nil {
		t.Errorf("expected nil for empty logs, got %v", dist)
	}
}

func TestComputeTrend_Sparse(t *testing.T) {
	values := []DataPoint{
		{Timestamp: "2024-01-01T00:00:00Z", Value: "0"},
		{Timestamp: "2024-01-01T00:01:00Z", Value: "0"},
		{Timestamp: "2024-01-01T00:02:00Z", Value: "0"},
	}
	summary := computeTrend(values)
	if summary.Trend != "sparse" {
		t.Errorf("expected trend=sparse, got %q", summary.Trend)
	}
}

func TestComputeTrend_NonZeroPct(t *testing.T) {
	values := []DataPoint{
		{Value: "0"}, {Value: "5"}, {Value: "0"}, {Value: "0"}, {Value: "3"},
	}
	summary := computeTrend(values)
	expected := 40.0
	if summary.NonZeroPct != expected {
		t.Errorf("expected non_zero_pct=%f, got %f", expected, summary.NonZeroPct)
	}
}

func TestSeriesKey(t *testing.T) {
	key := seriesKey(map[string]string{"service": "payments", "level": "error"})
	if key != "level=error,service=payments" {
		t.Errorf("expected sorted key, got %q", key)
	}
}

func TestSeriesKey_Empty(t *testing.T) {
	if seriesKey(nil) != "total" {
		t.Error("expected 'total' for empty labels")
	}
}

func TestExtractLogMessage_JSONWithMsg(t *testing.T) {
	line := `{"timestamp":"2024-01-01T00:00:00Z","level":"error","service":"payments","msg":"database query timeout after 30s","trace_id":"abc123"}`
	got := extractLogMessage(line)
	if got != "database query timeout after 30s" {
		t.Errorf("expected msg field, got %q", got)
	}
}

func TestExtractLogMessage_JSONWithMessage(t *testing.T) {
	line := `{"level":"error","message":"connection refused"}`
	got := extractLogMessage(line)
	if got != "connection refused" {
		t.Errorf("expected message field, got %q", got)
	}
}

func TestExtractLogMessage_JSONWithError(t *testing.T) {
	line := `{"level":"error","error":"null pointer exception"}`
	got := extractLogMessage(line)
	if got != "null pointer exception" {
		t.Errorf("expected error field, got %q", got)
	}
}

func TestExtractLogMessage_JSONWithoutMsgField(t *testing.T) {
	line := `{"level":"error","status_code":500}`
	got := extractLogMessage(line)
	if got != line {
		t.Errorf("expected original line when no msg field, got %q", got)
	}
}

func TestExtractLogMessage_EmptyMsg(t *testing.T) {
	line := `{"msg":"","level":"error"}`
	got := extractLogMessage(line)
	if got != line {
		t.Errorf("expected original line for empty msg, got %q", got)
	}
}

func TestExtractLogMessage_JSONWithLogKey(t *testing.T) {
	line := `{"log":"DB connection refused\n","stream":"stderr","time":"2024-01-15T14:32:05.123Z"}`
	got := extractLogMessage(line)
	if got != "DB connection refused" {
		t.Errorf("expected trimmed Docker log message, got %q", got)
	}
}

func TestExtractLogMessage_JSONWithLogKeyMultipleNewlines(t *testing.T) {
	line := `{"log":"connection pool exhausted\r\n","stream":"stderr"}`
	got := extractLogMessage(line)
	if got != "connection pool exhausted" {
		t.Errorf("expected trimmed message, got %q", got)
	}
}

func TestExtractLogMessage_JSONLogKeyEmpty(t *testing.T) {
	line := `{"log":"","stream":"stderr"}`
	got := extractLogMessage(line)
	if got != line {
		t.Errorf("expected original line for empty log key, got %q", got)
	}
}

func TestExtractPatterns_JSONLogs(t *testing.T) {
	logs := []LogEntry{
		{Line: `{"timestamp":"2024-01-01T00:00:00Z","level":"error","service":"payments","msg":"database query timeout after 30s","trace_id":"abc"}`},
		{Line: `{"timestamp":"2024-01-01T00:01:00Z","level":"error","service":"payments","msg":"database query timeout after 30s","trace_id":"def"}`},
		{Line: `{"timestamp":"2024-01-01T00:02:00Z","level":"error","service":"payments","msg":"connection refused","trace_id":"ghi"}`},
	}
	patterns, _ := extractPatterns(logs, 5)
	if len(patterns) != 2 {
		t.Errorf("expected 2 patterns from JSON logs, got %d", len(patterns))
		for _, p := range patterns {
			t.Logf("  pattern: %q (count=%d)", p.Pattern, p.Count)
		}
	}
	if len(patterns) > 0 && patterns[0].Count != 2 {
		t.Errorf("expected top pattern count=2, got %d", patterns[0].Count)
	}
}

func TestCollectLabelNames(t *testing.T) {
	logs := []LogEntry{
		{Labels: map[string]string{"service": "payments", "level": "error"}},
		{Labels: map[string]string{"service": "orders", "env": "production"}},
		{Labels: map[string]string{"job": "gateway"}},
	}
	names := collectLabelNames(logs)
	if len(names) != 4 {
		t.Fatalf("expected 4 label names, got %d: %v", len(names), names)
	}
	if names[0] != "env" || names[1] != "job" || names[2] != "level" || names[3] != "service" {
		t.Errorf("expected [env job level service], got %v", names)
	}
}

func TestCollectLabelNames_Empty(t *testing.T) {
	names := collectLabelNames(nil)
	if len(names) != 0 {
		t.Errorf("expected empty for nil logs, got %v", names)
	}
}

func TestExtractPatterns_JSONSampleIsCleanMessage(t *testing.T) {
	logs := []LogEntry{
		{Line: `{"level":"error","msg":"connection timeout","trace_id":"abc"}`},
		{Line: `{"level":"error","msg":"connection timeout","trace_id":"def"}`},
	}
	patterns, _ := extractPatterns(logs, 5)
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}
	if patterns[0].Sample != "connection timeout" {
		t.Errorf("expected clean sample 'connection timeout', got %q", patterns[0].Sample)
	}
}

func TestComputeTrend_Avg(t *testing.T) {
	values := []DataPoint{
		{Value: "2"}, {Value: "4"}, {Value: "6"}, {Value: "8"}, {Value: "10"},
	}
	summary := computeTrend(values)
	expectedAvg := 6.0
	if summary.Avg != expectedAvg {
		t.Errorf("expected avg=%f, got %f", expectedAvg, summary.Avg)
	}
}

func TestComputeTrend_TwoDataPoints_NonZero(t *testing.T) {
	values := []DataPoint{
		{Value: "10"}, {Value: "50"},
	}
	summary := computeTrend(values)
	if summary.Trend != "stable" {
		t.Errorf("expected trend=stable for 2 non-zero data points, got %q", summary.Trend)
	}
	if summary.Avg != 30 {
		t.Errorf("expected avg=30, got %f", summary.Avg)
	}
}

func TestComputeTrend_TwoDataPoints_AllZero(t *testing.T) {
	values := []DataPoint{
		{Value: "0"}, {Value: "0"},
	}
	summary := computeTrend(values)
	if summary.Trend != "sparse" {
		t.Errorf("expected trend=sparse for 2 zero data points, got %q", summary.Trend)
	}
}

func TestExtractPatterns_PctRoundedToOneDecimal(t *testing.T) {
	logs := []LogEntry{
		{Line: "error type A"},
		{Line: "error type B"},
		{Line: "error type C"},
	}
	patterns, _ := extractPatterns(logs, 5)
	for _, p := range patterns {
		if p.Pct != 33.3 {
			t.Errorf("expected pct=33.3 for 1/3, got %f", p.Pct)
		}
	}
}

func TestExtractPatterns_SampleTruncated(t *testing.T) {
	longMsg := ""
	for i := 0; i < 300; i++ {
		longMsg += "x"
	}
	logs := []LogEntry{
		{Line: longMsg},
		{Line: longMsg},
		{Line: longMsg},
	}
	patterns, _ := extractPatterns(logs, 5)
	if len(patterns) == 0 {
		t.Fatal("expected patterns")
	}
	if len(patterns[0].Sample) > 210 {
		t.Errorf("expected sample to be truncated, got length %d", len(patterns[0].Sample))
	}
	if len(patterns[0].Sample) > 200 && patterns[0].Sample[len(patterns[0].Sample)-3:] != "..." {
		t.Error("expected truncated sample to end with '...'")
	}
}

func TestComputeTrend_ZeroStartIncreasing(t *testing.T) {
	values := []DataPoint{
		{Value: "0"}, {Value: "0"}, {Value: "0"},
		{Value: "0"}, {Value: "0"}, {Value: "0"},
		{Value: "5"}, {Value: "8"}, {Value: "12"},
	}
	summary := computeTrend(values)
	if summary.Trend != "increasing" {
		t.Errorf("expected trend=increasing for zero-start, got %q", summary.Trend)
	}
}

func TestComputeTrend_FloatsRounded(t *testing.T) {
	values := []DataPoint{
		{Timestamp: "2024-01-01T00:00:00Z", Value: "1.333"},
		{Timestamp: "2024-01-01T00:01:00Z", Value: "2.666"},
		{Timestamp: "2024-01-01T00:02:00Z", Value: "0"},
	}
	summary := computeTrend(values)
	if summary.Total != 4.0 {
		t.Errorf("expected total=4.0, got %f", summary.Total)
	}
	if summary.Avg != 1.33 {
		t.Errorf("expected avg=1.33, got %f", summary.Avg)
	}
	if summary.Peak != 2.67 {
		t.Errorf("expected peak=2.67, got %f", summary.Peak)
	}
	if summary.NonZeroPct != 66.7 {
		t.Errorf("expected non_zero_pct=66.7, got %f", summary.NonZeroPct)
	}
}

func TestDownsampleDataPoints(t *testing.T) {
	values := make([]DataPoint, 60)
	for i := range values {
		values[i] = DataPoint{
			Timestamp: fmt.Sprintf("2024-01-01T00:%02d:00Z", i),
			Value:     fmt.Sprintf("%d", i),
		}
	}
	result := downsampleDataPoints(values, 24)

	if len(result) != 24 {
		t.Fatalf("expected 24 points, got %d", len(result))
	}
	if result[0].Timestamp != values[0].Timestamp {
		t.Errorf("first point not preserved: got %s", result[0].Timestamp)
	}
	if result[23].Timestamp != values[59].Timestamp {
		t.Errorf("last point not preserved: got %s", result[23].Timestamp)
	}
}

func TestDownsampleDataPoints_NoOpWhenSmall(t *testing.T) {
	values := []DataPoint{
		{Timestamp: "t1", Value: "1"},
		{Timestamp: "t2", Value: "2"},
		{Timestamp: "t3", Value: "3"},
	}
	result := downsampleDataPoints(values, 24)
	if len(result) != 3 {
		t.Errorf("expected 3 points unchanged, got %d", len(result))
	}
}

func TestAutoSelectStep(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"15m range", 15 * time.Minute, "30s"},
		{"30m range", 30 * time.Minute, "30s"},
		{"1h range", 1 * time.Hour, "1m"},
		{"2h range", 2 * time.Hour, "1m"},
		{"3h range", 3 * time.Hour, "5m"},
		{"6h range", 6 * time.Hour, "5m"},
		{"8h range", 8 * time.Hour, "15m"},
		{"12h range", 12 * time.Hour, "15m"},
		{"24h range", 24 * time.Hour, "1h"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start := now.Add(-tc.duration)
			got := autoSelectStep(start, now)
			if got != tc.expected {
				t.Errorf("autoSelectStep(%v) = %q, want %q", tc.duration, got, tc.expected)
			}
		})
	}
}

func TestExtractLogMessage_NestedErrorObject(t *testing.T) {
	line := `{"level":"error","error":{"message":"connection timeout after 30s","code":"ETIMEDOUT"}}`
	got := extractLogMessage(line)
	if got != "connection timeout after 30s" {
		t.Errorf("expected nested error.message, got %q", got)
	}
}

func TestExtractLogMessage_NestedErrWithMsg(t *testing.T) {
	line := `{"level":"error","err":{"msg":"pool exhausted","stack":"..."}}`
	got := extractLogMessage(line)
	if got != "pool exhausted" {
		t.Errorf("expected nested err.msg, got %q", got)
	}
}

func TestExtractLogMessage_NestedErrorEmptyMessage(t *testing.T) {
	line := `{"level":"error","error":{"message":"","code":"UNKNOWN"}}`
	got := extractLogMessage(line)
	if got != line {
		t.Errorf("expected original line for empty nested message, got %q", got)
	}
}

func TestComputeTrend_NaN(t *testing.T) {
	values := []DataPoint{
		{Timestamp: "2024-01-01T00:00:00Z", Value: "5"},
		{Timestamp: "2024-01-01T00:01:00Z", Value: "NaN"},
		{Timestamp: "2024-01-01T00:02:00Z", Value: "10"},
		{Timestamp: "2024-01-01T00:03:00Z", Value: "NaN"},
		{Timestamp: "2024-01-01T00:04:00Z", Value: "15"},
	}
	summary := computeTrend(values)

	if summary.Total != 30 {
		t.Errorf("expected total=30 (skipping NaN), got %f", summary.Total)
	}
	if summary.Peak != 15 {
		t.Errorf("expected peak=15, got %f", summary.Peak)
	}
	if summary.Latest != 15 {
		t.Errorf("expected latest=15 (last valid value), got %f", summary.Latest)
	}
	if summary.Avg != 10 {
		t.Errorf("expected avg=10, got %f", summary.Avg)
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal failed -- NaN leaked into TrendSummary: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON output")
	}
}

func TestComputeTrend_AllNaN(t *testing.T) {
	values := []DataPoint{
		{Timestamp: "2024-01-01T00:00:00Z", Value: "NaN"},
		{Timestamp: "2024-01-01T00:01:00Z", Value: "NaN"},
		{Timestamp: "2024-01-01T00:02:00Z", Value: "NaN"},
	}
	summary := computeTrend(values)
	if summary.Trend != "sparse" {
		t.Errorf("expected trend=sparse for all-NaN, got %q", summary.Trend)
	}
	if _, err := json.Marshal(summary); err != nil {
		t.Fatalf("json.Marshal failed for all-NaN: %v", err)
	}
}

func TestComputeTrend_Inf(t *testing.T) {
	values := []DataPoint{
		{Timestamp: "2024-01-01T00:00:00Z", Value: "5"},
		{Timestamp: "2024-01-01T00:01:00Z", Value: "+Inf"},
		{Timestamp: "2024-01-01T00:02:00Z", Value: "-Inf"},
		{Timestamp: "2024-01-01T00:03:00Z", Value: "10"},
	}
	summary := computeTrend(values)
	if summary.Total != 15 {
		t.Errorf("expected total=15 (skipping Inf), got %f", summary.Total)
	}
	if _, err := json.Marshal(summary); err != nil {
		t.Fatalf("json.Marshal failed -- Inf leaked: %v", err)
	}
}

func TestSafeParseFloat(t *testing.T) {
	tests := []struct {
		input string
		val   float64
		ok    bool
	}{
		{"42", 42, true},
		{"3.14", 3.14, true},
		{"0", 0, true},
		{"NaN", 0, false},
		{"+Inf", 0, false},
		{"-Inf", 0, false},
		{"not_a_number", 0, false},
		{"", 0, false},
	}
	for _, tc := range tests {
		v, ok := safeParseFloat(tc.input)
		if ok != tc.ok {
			t.Errorf("safeParseFloat(%q): ok=%v, want %v", tc.input, ok, tc.ok)
		}
		if ok && v != tc.val {
			t.Errorf("safeParseFloat(%q): val=%f, want %f", tc.input, v, tc.val)
		}
	}
}

func TestExtractLogMessage_Logfmt_Table(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "quoted msg",
			input:    `level=error msg="DB connection refused" service=payments trace_id=abc123`,
			expected: "DB connection refused",
		},
		{
			name:     "unquoted msg",
			input:    `level=error msg=timeout service=gateway`,
			expected: "timeout",
		},
		{
			name:     "message key",
			input:    `level=warn message="rate limit exceeded" user_id=u123`,
			expected: "rate limit exceeded",
		},
		{
			name:     "error key",
			input:    `level=error error="null pointer exception" stack="..."`,
			expected: "null pointer exception",
		},
		{
			name:     "msg at end of line",
			input:    `level=error service=payments msg="connection pool exhausted"`,
			expected: "connection pool exhausted",
		},
		{
			name:     "unquoted msg at end",
			input:    `level=error service=payments msg=timeout`,
			expected: "timeout",
		},
		{
			name:     "not logfmt -- no key= pattern",
			input:    "plain error message without structure",
			expected: "plain error message without structure",
		},
		{
			name:     "msg embedded in word -- should not match",
			input:    `submsg="not this" level=error`,
			expected: `submsg="not this" level=error`,
		},
		{
			name:     "msg= after similar key -- should skip prefix match and find real key",
			input:    `customer_msg=irrelevant msg="DB connection refused" service=payments`,
			expected: "DB connection refused",
		},
		{
			name:     "error= after similar key -- should skip prefix match",
			input:    `prev_error=old error="new failure" level=error`,
			expected: "new failure",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractLogMessage(tc.input)
			if got != tc.expected {
				t.Errorf("extractLogMessage(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestExtractLogMessage_AdditionalJSONKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "error_message key",
			input:    `{"level":"error","error_message":"insufficient funds for withdrawal","account":"ACC-9821"}`,
			expected: "insufficient funds for withdrawal",
		},
		{
			name:     "reason key",
			input:    `{"level":"warn","reason":"rate limit exceeded for partner API","partner_id":"stripe"}`,
			expected: "rate limit exceeded for partner API",
		},
		{
			name:     "detail key",
			input:    `{"level":"error","detail":"TLS handshake timeout after 30s","host":"payments-db.internal"}`,
			expected: "TLS handshake timeout after 30s",
		},
		{
			name:     "msg still takes priority over reason",
			input:    `{"msg":"primary message","reason":"secondary reason"}`,
			expected: "primary message",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractLogMessage(tc.input)
			if got != tc.expected {
				t.Errorf("extractLogMessage(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestExtractLogMessage_AdditionalLogfmtKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "error_message logfmt",
			input:    `level=error error_message="transaction rollback failed" tx_id=TX-1234`,
			expected: "transaction rollback failed",
		},
		{
			name:     "reason logfmt",
			input:    `level=warn reason="circuit breaker open" service=payments`,
			expected: "circuit breaker open",
		},
		{
			name:     "detail logfmt",
			input:    `level=error detail="connection pool exhausted" pool_size=50`,
			expected: "connection pool exhausted",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractLogMessage(tc.input)
			if got != tc.expected {
				t.Errorf("extractLogMessage(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestExtractPatterns_DockerAndRegularLogsGroupTogether(t *testing.T) {
	logs := []LogEntry{
		{Line: `{"log":"connection timeout\n","stream":"stderr"}`},
		{Line: `{"log":"connection timeout\n","stream":"stderr"}`},
		{Line: `{"msg":"connection timeout","level":"error"}`},
	}
	patterns, _ := extractPatterns(logs, 5)
	if len(patterns) != 1 {
		t.Errorf("expected 1 unified pattern for Docker + regular logs, got %d", len(patterns))
		for _, p := range patterns {
			t.Logf("  pattern: %q (count=%d)", p.Pattern, p.Count)
		}
	}
	if len(patterns) > 0 && patterns[0].Count != 3 {
		t.Errorf("expected count=3, got %d", patterns[0].Count)
	}
}

func TestExtractPatterns_LogfmtLogs(t *testing.T) {
	logs := []LogEntry{
		{Line: `level=error msg="connection timeout" service=payments trace_id=abc`},
		{Line: `level=error msg="connection timeout" service=payments trace_id=def`},
		{Line: `level=error msg="rate limit exceeded" service=gateway user=u123`},
	}
	patterns, _ := extractPatterns(logs, 5)
	if len(patterns) != 2 {
		t.Errorf("expected 2 patterns from logfmt logs, got %d", len(patterns))
		for _, p := range patterns {
			t.Logf("  pattern: %q (count=%d)", p.Pattern, p.Count)
		}
	}
	if len(patterns) > 0 && patterns[0].Count != 2 {
		t.Errorf("expected top pattern count=2, got %d", patterns[0].Count)
	}
	if len(patterns) > 0 && patterns[0].Sample != "connection timeout" {
		t.Errorf("expected clean sample, got %q", patterns[0].Sample)
	}
}

func TestCollectLabelNames_FiltersInternalLabels(t *testing.T) {
	logs := []LogEntry{
		{Labels: map[string]string{"service": "payments", "__stream_shard__": "0", "__name__": "logs"}},
		{Labels: map[string]string{"service": "orders", "__stream_shard__": "1"}},
	}
	names := collectLabelNames(logs)
	if len(names) != 1 {
		t.Fatalf("expected 1 label name (service), got %d: %v", len(names), names)
	}
	if names[0] != "service" {
		t.Errorf("expected [service], got %v", names)
	}
}

func TestExtractPatterns_TotalPatterns(t *testing.T) {
	logs := make([]LogEntry, 0)
	for i := 0; i < 15; i++ {
		logs = append(logs, LogEntry{Line: fmt.Sprintf("unique error type %d", i)})
	}
	patterns, totalPatterns := extractPatterns(logs, 5)
	if len(patterns) != 5 {
		t.Errorf("expected 5 patterns after truncation, got %d", len(patterns))
	}
	if totalPatterns != 15 {
		t.Errorf("expected totalPatterns=15, got %d", totalPatterns)
	}
}

func TestQueryLogsOutput_DirectionField(t *testing.T) {
	out := QueryLogsOutput{
		Logs:      []LogEntry{},
		TotalLogs: 0,
		Direction: "forward",
		Query:     `{service="payments"}`,
		TimeRange: "2024-01-01T00:00:00Z to 2024-01-01T01:00:00Z",
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["direction"] != "forward" {
		t.Errorf("expected direction='forward', got %v", parsed["direction"])
	}

	out.Direction = "backward"
	data, err = json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	parsed = nil
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["direction"] != "backward" {
		t.Errorf("expected direction='backward', got %v", parsed["direction"])
	}
}

func TestExtractLabelDistribution_NestedStructure(t *testing.T) {
	logs := []LogEntry{
		{Labels: map[string]string{"service": "payments", "level": "error"}},
		{Labels: map[string]string{"service": "payments", "level": "warn"}},
		{Labels: map[string]string{"service": "orders", "level": "error"}},
	}
	serviceDist := extractLabelDistribution(logs, "service")
	if serviceDist == nil {
		t.Fatal("expected service distribution")
	}
	if serviceDist["payments"] != 2 || serviceDist["orders"] != 1 {
		t.Errorf("unexpected service distribution: %v", serviceDist)
	}

	levelDist := extractLabelDistribution(logs, "level")
	if levelDist == nil {
		t.Fatal("expected level distribution")
	}
	if levelDist["error"] != 2 || levelDist["warn"] != 1 {
		t.Errorf("unexpected level distribution: %v", levelDist)
	}
}

func TestTruncateRuneSafe(t *testing.T) {
	text := "abc\u20acdef"
	if got := truncateRuneSafe(text, 4); got != "abc" {
		t.Errorf("truncateRuneSafe(%q, 4) = %q, want %q", text, got, "abc")
	}
	if got := truncateRuneSafe(text, 5); got != "abc" {
		t.Errorf("truncateRuneSafe(%q, 5) = %q, want %q", text, got, "abc")
	}
	if got := truncateRuneSafe(text, 6); got != "abc\u20ac" {
		t.Errorf("truncateRuneSafe(%q, 6) = %q, want %q", text, got, "abc\u20ac")
	}
	if got := truncateRuneSafe(text, 3); got != "abc" {
		t.Errorf("truncateRuneSafe(%q, 3) = %q, want %q", text, got, "abc")
	}
	if got := truncateRuneSafe(text, 100); got != text {
		t.Errorf("truncateRuneSafe(%q, 100) = %q, want %q", text, got, text)
	}
}

func TestExtractPatterns_MultibyteSafety(t *testing.T) {
	prefix := strings.Repeat("x", 199) + "\u20ac" + "tail"
	logs := []LogEntry{
		{Line: prefix},
		{Line: prefix},
		{Line: prefix},
	}
	patterns, _ := extractPatterns(logs, 5)
	if len(patterns) == 0 {
		t.Fatal("expected patterns")
	}
	if !utf8.ValidString(patterns[0].Pattern) {
		t.Errorf("pattern contains invalid UTF-8: %q", patterns[0].Pattern)
	}
	if !utf8.ValidString(patterns[0].Sample) {
		t.Errorf("sample contains invalid UTF-8: %q", patterns[0].Sample)
	}
}

func TestAvgPerMinute_PreComputed(t *testing.T) {
	values := make([]DataPoint, 12)
	for i := range values {
		values[i] = DataPoint{
			Timestamp: fmt.Sprintf("2024-01-15T14:%02d:00Z", i*5),
			Value:     "115",
		}
	}
	summary := computeTrend(values)
	stepMinutes := stepToMinutes("5m")
	avgPerMin := math.Round(summary.Avg/stepMinutes*100) / 100
	if avgPerMin != 23 {
		t.Errorf("expected avg_per_minute=23 for step=5m avg=115, got %v", avgPerMin)
	}

	summary2 := computeTrend(values)
	stepMinutes2 := stepToMinutes("30s")
	avgPerMin2 := math.Round(summary2.Avg/stepMinutes2*100) / 100
	if avgPerMin2 != 230 {
		t.Errorf("expected avg_per_minute=230 for step=30s avg=115, got %v", avgPerMin2)
	}
}

func TestAvgPerMinute_ZeroStep(t *testing.T) {
	stepMinutes := stepToMinutes("")
	if stepMinutes != 0 {
		t.Errorf("expected 0 for empty step, got %v", stepMinutes)
	}
}

// ===========================================================================
// Adversarial tests (new)
// ===========================================================================

// ---------------------------------------------------------------------------
// computeTrend -- adversarial
// ---------------------------------------------------------------------------

func TestComputeTrend_EmptyValues(t *testing.T) {
	result := computeTrend(nil)
	if result.Trend != "sparse" {
		t.Fatalf("expected trend 'sparse' for nil slice, got %q", result.Trend)
	}

	result2 := computeTrend([]DataPoint{})
	if result2.Trend != "sparse" {
		t.Fatalf("expected trend 'sparse' for empty slice, got %q", result2.Trend)
	}
}

func TestComputeTrend_SinglePoint(t *testing.T) {
	result := computeTrend([]DataPoint{
		{Timestamp: "2024-01-15T00:00:00Z", Value: "42"},
	})
	if result.Total != 42 {
		t.Fatalf("expected Total=42, got %v", result.Total)
	}
	if result.Peak != 42 {
		t.Fatalf("expected Peak=42, got %v", result.Peak)
	}
	// validCount=1 (<3), total!=0 => trend="stable"
	if result.Trend != "stable" {
		t.Fatalf("expected trend 'stable' for single non-zero point, got %q", result.Trend)
	}
}

func TestComputeTrend_AllZeros(t *testing.T) {
	values := make([]DataPoint, 5)
	for i := range values {
		values[i] = DataPoint{
			Timestamp: fmt.Sprintf("2024-01-15T00:%02d:00Z", i),
			Value:     "0",
		}
	}
	result := computeTrend(values)
	if result.Total != 0 {
		t.Fatalf("expected Total=0, got %v", result.Total)
	}
	if result.Trend != "sparse" {
		t.Fatalf("expected trend 'sparse' for all-zeros, got %q", result.Trend)
	}
}

func TestComputeTrend_NaNValues(t *testing.T) {
	values := []DataPoint{
		{Value: "NaN"},
		{Value: "Inf"},
		{Value: "-Inf"},
		{Value: "not_a_number"},
	}
	// Must not panic.
	result := computeTrend(values)
	// All values are unparseable so validCount=0 => sparse.
	if result.Trend != "sparse" {
		t.Fatalf("expected trend 'sparse' for all-unparseable values, got %q", result.Trend)
	}
}

func TestComputeTrend_Increasing(t *testing.T) {
	raw := []float64{1, 2, 3, 5, 8, 13, 21}
	values := make([]DataPoint, len(raw))
	for i, v := range raw {
		values[i] = DataPoint{
			Timestamp: fmt.Sprintf("2024-01-15T00:%02d:00Z", i),
			Value:     fmt.Sprintf("%v", v),
		}
	}
	result := computeTrend(values)
	if result.Trend != "increasing" {
		t.Fatalf("expected trend 'increasing', got %q", result.Trend)
	}
}

func TestComputeTrend_Decreasing(t *testing.T) {
	raw := []float64{20, 15, 10, 5, 3, 1}
	values := make([]DataPoint, len(raw))
	for i, v := range raw {
		values[i] = DataPoint{
			Timestamp: fmt.Sprintf("2024-01-15T00:%02d:00Z", i),
			Value:     fmt.Sprintf("%v", v),
		}
	}
	result := computeTrend(values)
	if result.Trend != "decreasing" {
		t.Fatalf("expected trend 'decreasing', got %q", result.Trend)
	}
}

func TestComputeTrend_Stable(t *testing.T) {
	values := make([]DataPoint, 5)
	for i := range values {
		values[i] = DataPoint{
			Timestamp: fmt.Sprintf("2024-01-15T00:%02d:00Z", i),
			Value:     "10",
		}
	}
	result := computeTrend(values)
	if result.Trend != "stable" {
		t.Fatalf("expected trend 'stable', got %q", result.Trend)
	}
}

// ---------------------------------------------------------------------------
// downsampleDataPoints -- adversarial
// ---------------------------------------------------------------------------

func TestDownsampleDataPoints_LessThanMax(t *testing.T) {
	values := make([]DataPoint, 5)
	for i := range values {
		values[i] = DataPoint{Value: fmt.Sprintf("%d", i)}
	}
	result := downsampleDataPoints(values, 24)
	if len(result) != 5 {
		t.Fatalf("expected 5 points, got %d", len(result))
	}
	for i := range result {
		if result[i].Value != values[i].Value {
			t.Fatalf("point %d differs: %q vs %q", i, result[i].Value, values[i].Value)
		}
	}
}

func TestDownsampleDataPoints_ExactlyMax(t *testing.T) {
	values := make([]DataPoint, 24)
	for i := range values {
		values[i] = DataPoint{Value: fmt.Sprintf("%d", i)}
	}
	result := downsampleDataPoints(values, 24)
	if len(result) != 24 {
		t.Fatalf("expected 24 points, got %d", len(result))
	}
}

func TestDownsampleDataPoints_NeedsDownsampling(t *testing.T) {
	values := make([]DataPoint, 100)
	for i := range values {
		values[i] = DataPoint{
			Timestamp: fmt.Sprintf("t%d", i),
			Value:     fmt.Sprintf("%d", i),
		}
	}
	result := downsampleDataPoints(values, 24)
	if len(result) != 24 {
		t.Fatalf("expected 24 points, got %d", len(result))
	}
	// First point preserved.
	if result[0].Value != values[0].Value {
		t.Fatalf("first point not preserved: got %q, want %q", result[0].Value, values[0].Value)
	}
	// Last point preserved.
	if result[len(result)-1].Value != values[len(values)-1].Value {
		t.Fatalf("last point not preserved: got %q, want %q",
			result[len(result)-1].Value, values[len(values)-1].Value)
	}
}

func TestDownsampleDataPoints_SinglePoint(t *testing.T) {
	values := []DataPoint{{Value: "1"}}
	result := downsampleDataPoints(values, 24)
	if len(result) != 1 {
		t.Fatalf("expected 1 point, got %d", len(result))
	}
}

func TestDownsampleDataPoints_TwoPoints(t *testing.T) {
	values := []DataPoint{{Value: "1"}, {Value: "2"}}
	result := downsampleDataPoints(values, 24)
	if len(result) != 2 {
		t.Fatalf("expected 2 points, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// extractPatterns -- adversarial
// ---------------------------------------------------------------------------

func TestExtractPatterns_Empty(t *testing.T) {
	patterns, total := extractPatterns(nil, 10)
	if patterns != nil {
		t.Fatalf("expected nil patterns, got %v", patterns)
	}
	if total != 0 {
		t.Fatalf("expected total=0, got %d", total)
	}
}

func TestExtractPatterns_AllIdentical(t *testing.T) {
	logs := make([]LogEntry, 10)
	for i := range logs {
		logs[i] = LogEntry{Line: "connection refused to host"}
	}
	patterns, _ := extractPatterns(logs, 10)
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}
	if patterns[0].Count != 10 {
		t.Fatalf("expected Count=10, got %d", patterns[0].Count)
	}
	if patterns[0].Pct != 100 {
		t.Fatalf("expected Pct=100, got %v", patterns[0].Pct)
	}
}

func TestExtractPatterns_AllUnique(t *testing.T) {
	logs := make([]LogEntry, 10)
	for i := range logs {
		logs[i] = LogEntry{Line: fmt.Sprintf("unique message number %d", i)}
	}
	patterns, _ := extractPatterns(logs, 20)
	if len(patterns) != 10 {
		t.Fatalf("expected 10 patterns, got %d", len(patterns))
	}
}

func TestExtractPatterns_UUIDNormalization(t *testing.T) {
	logs := []LogEntry{
		{Line: "request failed for user 550e8400-e29b-41d4-a716-446655440000"},
		{Line: "request failed for user a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
	}
	patterns, _ := extractPatterns(logs, 10)
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern (UUIDs normalized), got %d", len(patterns))
	}
}

func TestExtractPatterns_IPNormalization(t *testing.T) {
	logs := []LogEntry{
		{Line: "connection from 192.168.1.1 refused"},
		{Line: "connection from 10.0.0.42 refused"},
	}
	patterns, _ := extractPatterns(logs, 10)
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern (IPs normalized), got %d", len(patterns))
	}
}

// ---------------------------------------------------------------------------
// AnalyzeLogs -- adversarial
// ---------------------------------------------------------------------------

func TestAnalyzeLogs_EmptyLogs(t *testing.T) {
	out := &QueryLogsOutput{}
	AnalyzeLogs(out, 100)
	if out.TotalLogs != 0 {
		t.Fatalf("expected TotalLogs=0, got %d", out.TotalLogs)
	}
	if out.TopPatterns != nil {
		t.Fatalf("expected nil TopPatterns, got %v", out.TopPatterns)
	}
	if out.UniqueLabels != nil {
		t.Fatalf("expected nil UniqueLabels, got %v", out.UniqueLabels)
	}
}

func TestAnalyzeLogs_SingleLog(t *testing.T) {
	out := &QueryLogsOutput{
		Logs: []LogEntry{{Line: "hello", Timestamp: "2024-01-15T00:00:00Z"}},
	}
	AnalyzeLogs(out, 100)
	if out.TotalLogs != 1 {
		t.Fatalf("expected TotalLogs=1, got %d", out.TotalLogs)
	}
	if out.TopPatterns != nil {
		t.Fatalf("expected nil TopPatterns for <3 logs, got %v", out.TopPatterns)
	}
}

func TestAnalyzeLogs_TwoLogs(t *testing.T) {
	out := &QueryLogsOutput{
		Logs: []LogEntry{
			{Line: "line1", Timestamp: "2024-01-15T00:00:00Z"},
			{Line: "line2", Timestamp: "2024-01-15T00:01:00Z"},
		},
	}
	AnalyzeLogs(out, 100)
	if out.TotalLogs != 2 {
		t.Fatalf("expected TotalLogs=2, got %d", out.TotalLogs)
	}
	if out.TopPatterns != nil {
		t.Fatalf("expected nil TopPatterns for <3 logs, got %v", out.TopPatterns)
	}
}

// ---------------------------------------------------------------------------
// AnalyzeStats -- adversarial
// ---------------------------------------------------------------------------

func TestAnalyzeStats_EmptySeries(t *testing.T) {
	out := &QueryStatsOutput{}
	AnalyzeStats(out)
	if out.TotalSeries != 0 {
		t.Fatalf("expected TotalSeries=0, got %d", out.TotalSeries)
	}
	if out.Summaries != nil {
		t.Fatalf("expected nil Summaries, got %v", out.Summaries)
	}
}

func TestAnalyzeStats_UnparseableStep(t *testing.T) {
	out := &QueryStatsOutput{
		Step: "invalid",
		Series: []MetricSeries{
			{
				Labels: map[string]string{"app": "test"},
				Values: []DataPoint{
					{Value: "10"},
					{Value: "20"},
					{Value: "30"},
				},
			},
		},
	}
	AnalyzeStats(out)
	key := "app=test"
	summary, ok := out.Summaries[key]
	if !ok {
		t.Fatalf("expected summary for key %q", key)
	}
	// stepToMinutes("invalid") returns 0, so AvgPerMinute should remain 0.
	if summary.AvgPerMinute != 0 {
		t.Fatalf("expected AvgPerMinute=0 for unparseable step, got %v", summary.AvgPerMinute)
	}
}

// ---------------------------------------------------------------------------
// ParseTimeOrDefault -- adversarial
// ---------------------------------------------------------------------------

const timeTolerance = 2 * time.Second

func TestParseTimeOrDefault_Empty(t *testing.T) {
	result, err := ParseTimeOrDefault("", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := time.Now().Add(-time.Hour)
	if diff := absDuration(result.Sub(expected)); diff > timeTolerance {
		t.Fatalf("expected ~1h ago, got %v (diff %v)", result, diff)
	}
}

func TestParseTimeOrDefault_Now(t *testing.T) {
	result, err := ParseTimeOrDefault("now", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := absDuration(time.Since(result)); diff > timeTolerance {
		t.Fatalf("expected ~now, got %v (diff %v)", result, diff)
	}
}

func TestParseTimeOrDefault_Relative(t *testing.T) {
	result, err := ParseTimeOrDefault("30m ago", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := time.Now().Add(-30 * time.Minute)
	if diff := absDuration(result.Sub(expected)); diff > timeTolerance {
		t.Fatalf("expected ~30m ago, got %v (diff %v)", result, diff)
	}
}

func TestParseTimeOrDefault_MalformedTime(t *testing.T) {
	_, err := ParseTimeOrDefault("not a real time", 0)
	if err == nil {
		t.Fatal("expected error for malformed time, got nil")
	}
}

func TestParseTimeOrDefault_RFC3339(t *testing.T) {
	input := "2024-01-15T14:00:00Z"
	result, err := ParseTimeOrDefault(input, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected, _ := time.Parse(time.RFC3339, input)
	if !result.Equal(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
}

func TestParseTimeOrDefault_HugeRelativeTime(t *testing.T) {
	// Must not panic even with an extremely large duration.
	_, err := ParseTimeOrDefault("999999h ago", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseTimeOrDefault_LowercaseRFC3339(t *testing.T) {
	// Production bug: Gemini generates "2026-03-10t17:02:09z" (lowercase t and z)
	// which time.Parse(time.RFC3339, ...) rejects.
	cases := []struct {
		input    string
		expected string
	}{
		{"2026-03-10t17:02:09z", "2026-03-10T17:02:09Z"},
		{"2024-01-15t10:30:00z", "2024-01-15T10:30:00Z"},
		{"2025-06-01t00:00:00+05:30", "2025-06-01T00:00:00+05:30"},
	}
	for _, tc := range cases {
		result, err := ParseTimeOrDefault(tc.input, 0)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.input, err)
			continue
		}
		expected, _ := time.Parse(time.RFC3339, tc.expected)
		if !result.Equal(expected) {
			t.Errorf("%q: expected %v, got %v", tc.input, expected, result)
		}
	}
}

// ---------------------------------------------------------------------------
// TruncateLogLine -- adversarial
// ---------------------------------------------------------------------------

func TestTruncateLogLine_Short(t *testing.T) {
	input := "short line"
	result := TruncateLogLine(input)
	if result != input {
		t.Fatalf("expected %q, got %q", input, result)
	}
}

func TestTruncateLogLine_ExactlyMax(t *testing.T) {
	input := strings.Repeat("x", maxLogLineLength)
	result := TruncateLogLine(input)
	if result != input {
		t.Fatalf("expected unchanged string of len %d, got len %d", maxLogLineLength, len(result))
	}
}

func TestTruncateLogLine_OverMax(t *testing.T) {
	input := strings.Repeat("x", maxLogLineLength+100)
	result := TruncateLogLine(input)
	if !strings.HasSuffix(result, "\u2026[truncated]") {
		t.Fatalf("expected truncation suffix, got trailing: %q", result[len(result)-30:])
	}
	if len(result) > maxLogLineLength+len("\u2026[truncated]") {
		t.Fatalf("truncated result too long: %d", len(result))
	}
}

func TestTruncateLogLine_Unicode(t *testing.T) {
	// Build a string that places a multi-byte rune right at the maxLogLineLength boundary.
	// Fill up to maxLogLineLength-1 with ASCII, then add a 3-byte rune (U+2603 SNOWMAN).
	prefix := strings.Repeat("a", maxLogLineLength-1)
	input := prefix + "\u2603" + strings.Repeat("b", 100)
	result := TruncateLogLine(input)
	if !strings.HasSuffix(result, "\u2026[truncated]") {
		t.Fatalf("expected truncation suffix")
	}
	// The truncated body (without suffix) must be valid UTF-8.
	body := strings.TrimSuffix(result, "\u2026[truncated]")
	for i, r := range body {
		if r == '\uFFFD' {
			t.Fatalf("replacement character at byte %d -- truncation split a rune", i)
		}
	}
}

// ---------------------------------------------------------------------------
// extractLogMessage -- adversarial
// ---------------------------------------------------------------------------

func TestExtractLogMessage_JSON(t *testing.T) {
	input := `{"msg":"hello world","level":"error"}`
	result := extractLogMessage(input)
	if result != "hello world" {
		t.Fatalf("expected 'hello world', got %q", result)
	}
}

func TestExtractLogMessage_JSONNoMsg(t *testing.T) {
	input := `{"status":"ok","code":200}`
	result := extractLogMessage(input)
	if result != input {
		t.Fatalf("expected raw line returned, got %q", result)
	}
}

func TestExtractLogMessage_Logfmt(t *testing.T) {
	input := `level=error msg="hello world" caller=main.go`
	result := extractLogMessage(input)
	if result != "hello world" {
		t.Fatalf("expected 'hello world', got %q", result)
	}
}

func TestExtractLogMessage_PlainText(t *testing.T) {
	input := "just a plain log line"
	result := extractLogMessage(input)
	if result != input {
		t.Fatalf("expected %q, got %q", input, result)
	}
}

func TestExtractLogMessage_Empty(t *testing.T) {
	result := extractLogMessage("")
	if result != "" {
		t.Fatalf("expected empty string, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// stepToMinutes -- adversarial
// ---------------------------------------------------------------------------

func TestStepToMinutes_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"5m", 5.0},
		{"1h", 60.0},
		{"30s", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := stepToMinutes(tc.input)
			if result != tc.expected {
				t.Fatalf("stepToMinutes(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestStepToMinutes_Invalid(t *testing.T) {
	result := stepToMinutes("invalid")
	if result != 0 {
		t.Fatalf("expected 0 for invalid step, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
