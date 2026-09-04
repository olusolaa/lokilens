package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/safety"
)

type staticLokiClient struct {
	queryRangeResponse *QueryResponse
}

func (c staticLokiClient) QueryRange(context.Context, QueryRangeRequest) (*QueryResponse, error) {
	return c.queryRangeResponse, nil
}

func (staticLokiClient) Query(context.Context, InstantQueryRequest) (*QueryResponse, error) {
	return nil, nil
}

func (staticLokiClient) Labels(context.Context, LabelsRequest) (*LabelsResponse, error) {
	return nil, nil
}

func (staticLokiClient) LabelValues(context.Context, LabelValuesRequest) (*LabelsResponse, error) {
	return nil, nil
}

func newTestToolHandlers(resp *QueryResponse) *ToolHandlers {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewToolHandlers(staticLokiClient{queryRangeResponse: resp}, safety.NewValidator(500), audit.New(logger))
}

func TestQueryLogs_EmptyResultUsesDescriptiveNote(t *testing.T) {
	resp := &QueryResponse{Data: QueryData{ResultType: "streams", Result: json.RawMessage(`[]`)}}
	out, err := newTestToolHandlers(resp).QueryLogs(context.Background(), QueryLogsInput{
		LogQL:     `{service="payments"}`,
		StartTime: "6h ago",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Warning != "" {
		t.Fatalf("expected no warning for empty-result guidance, got %q", out.Warning)
	}
	if !strings.Contains(out.Note, "Recommended follow-up for an empty result") {
		t.Fatalf("expected descriptive retry note, got %q", out.Note)
	}
	if strings.Contains(out.Note, "MANDATORY") || strings.Contains(out.Note, "Do NOT respond") {
		t.Fatalf("note must not read like a prompt instruction: %q", out.Note)
	}

	payload, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	if !strings.Contains(string(payload), `"note":`) {
		t.Fatalf("expected serialized note field, got %s", payload)
	}
	if strings.Contains(string(payload), `"warning":`) {
		t.Fatalf("did not expect serialized warning field, got %s", payload)
	}
}

func TestQueryStats_EmptyResultUsesDescriptiveNote(t *testing.T) {
	resp := &QueryResponse{Data: QueryData{ResultType: "matrix", Result: json.RawMessage(`[]`)}}
	out, err := newTestToolHandlers(resp).QueryStats(context.Background(), QueryStatsInput{
		LogQL:     `count_over_time({service="payments"}[5m])`,
		StartTime: "6h ago",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Warning != "" {
		t.Fatalf("expected no warning for empty-result guidance, got %q", out.Warning)
	}
	if !strings.Contains(out.Note, "Recommended follow-up for an empty result") {
		t.Fatalf("expected descriptive retry note, got %q", out.Note)
	}
	if strings.Contains(out.Note, "MANDATORY") || strings.Contains(out.Note, "Do NOT respond") {
		t.Fatalf("note must not read like a prompt instruction: %q", out.Note)
	}
}

func TestQueryLogs_EmptyResultPreservesOperationalWarning(t *testing.T) {
	resp := &QueryResponse{Data: QueryData{ResultType: "streams", Result: json.RawMessage(`[]`)}}
	out, err := newTestToolHandlers(resp).QueryLogs(context.Background(), QueryLogsInput{
		LogQL:     `{service="payments"}`,
		StartTime: "now",
		EndTime:   "1h ago",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.Warning, "swapped") {
		t.Fatalf("expected operational warning to be preserved, got %q", out.Warning)
	}
	if !strings.Contains(out.Note, "Recommended follow-up for an empty result") {
		t.Fatalf("expected descriptive retry note, got %q", out.Note)
	}
}

func TestQueryStats_EmptyResultDescribesAutoWidenWithoutOverclaiming(t *testing.T) {
	resp := &QueryResponse{Data: QueryData{ResultType: "matrix", Result: json.RawMessage(`[]`)}}
	out, err := newTestToolHandlers(resp).QueryStats(context.Background(), QueryStatsInput{
		LogQL: `count_over_time({service="payments"}[5m])`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.Warning, "auto-widened") {
		t.Fatalf("expected auto-widen operational warning, got %q", out.Warning)
	}
	if !strings.Contains(out.Note, "after auto-widening the search window") {
		t.Fatalf("expected auto-widen note, got %q", out.Note)
	}
	if strings.Contains(out.Note, "30 days") {
		t.Fatalf("note must not claim a range that the widening budget may not reach: %q", out.Note)
	}
}

func TestBuildQueryLogsOutput_TruncatesLongLogLines(t *testing.T) {
	longLine := strings.Repeat("x", 1500+500)
	ts := fmt.Sprintf("%d", time.Now().UnixNano())

	resp := &QueryResponse{
		Data: QueryData{
			ResultType: "streams",
		},
	}

	streams := []Stream{
		{
			Labels: map[string]string{"service": "payments"},
			Values: [][]string{{ts, longLine}},
		},
	}
	streamJSON, _ := json.Marshal(streams)
	resp.Data.Result = streamJSON

	out, err := buildQueryLogsOutput(resp, `{service="payments"}`, time.Now().Add(-time.Hour), time.Now(), 100, "backward")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(out.Logs))
	}

	line := out.Logs[0].Line
	if len(line) > 1500+50 {
		t.Errorf("log line should be truncated to ~1500 chars, got %d", len(line))
	}
	if !strings.HasSuffix(line, "…[truncated]") {
		t.Errorf("truncated line should end with '…[truncated]', got suffix: %q", line[len(line)-20:])
	}
}

func TestBuildQueryLogsOutput_ShortLinesUnchanged(t *testing.T) {
	shortLine := "2024-01-15T14:31:02Z error: connection refused"
	ts := fmt.Sprintf("%d", time.Now().UnixNano())

	resp := &QueryResponse{
		Data: QueryData{
			ResultType: "streams",
		},
	}
	streams := []Stream{
		{
			Labels: map[string]string{"service": "payments"},
			Values: [][]string{{ts, shortLine}},
		},
	}
	streamJSON, _ := json.Marshal(streams)
	resp.Data.Result = streamJSON

	out, err := buildQueryLogsOutput(resp, `{service="payments"}`, time.Now().Add(-time.Hour), time.Now(), 100, "backward")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(out.Logs))
	}
	if out.Logs[0].Line != shortLine {
		t.Errorf("short line should be unchanged, got %q", out.Logs[0].Line)
	}
}

func TestSanitizeTimeRange_NormalRange(t *testing.T) {
	now := time.Now()
	start := now.Add(-2 * time.Hour)

	sanitizedStart, _, warning := sanitizeTimeRange(start, now)
	if !sanitizedStart.Equal(start) {
		t.Errorf("expected no adjustment, but start was changed")
	}
	if warning != "" {
		t.Errorf("expected no warning, got %q", warning)
	}
}

func TestSanitizeTimeRange_WideRangeCapped(t *testing.T) {
	now := time.Now()
	start := now.Add(-7120 * time.Hour) // ~297 days, exceeds 30d limit

	sanitizedStart, sanitizedEnd, warning := sanitizeTimeRange(start, now)
	// Range should be capped to maxLokiQueryRange (30 days)
	actualRange := sanitizedEnd.Sub(sanitizedStart)
	if absDur(actualRange-maxLokiQueryRange) > 2*time.Second {
		t.Errorf("expected range capped to %v, got %v", maxLokiQueryRange, actualRange)
	}
	if !strings.Contains(warning, "capped to 30 days") {
		t.Errorf("expected 'capped to 30 days' in warning, got %q", warning)
	}
}

func TestSanitizeTimeRange_RangeWithin30Days(t *testing.T) {
	now := time.Now()
	start := now.Add(-15 * 24 * time.Hour) // 15 days — within limit

	sanitizedStart, _, warning := sanitizeTimeRange(start, now)
	if absDur(sanitizedStart.Sub(start)) > time.Second {
		t.Errorf("expected range preserved within 30d limit, but start was adjusted")
	}
	if warning != "" {
		t.Errorf("expected no warning for range within limit, got %q", warning)
	}
}

func TestSanitizeTimeRange_SwappedTimes(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)

	// Pass end before start (swapped)
	s, e, warning := sanitizeTimeRange(now, past)
	if !e.After(s) {
		t.Error("expected end after start after swap")
	}
	if !strings.Contains(warning, "swapped") {
		t.Errorf("expected 'swapped' in warning, got %q", warning)
	}
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func TestBuildQueryLogsOutput_TruncationIsUTF8Safe(t *testing.T) {
	prefix := strings.Repeat("x", 1500-1) + "€€€tail"
	ts := fmt.Sprintf("%d", time.Now().UnixNano())

	resp := &QueryResponse{
		Data: QueryData{
			ResultType: "streams",
		},
	}
	streams := []Stream{
		{
			Labels: map[string]string{"service": "payments"},
			Values: [][]string{{ts, prefix}},
		},
	}
	streamJSON, _ := json.Marshal(streams)
	resp.Data.Result = streamJSON

	out, err := buildQueryLogsOutput(resp, `{service="payments"}`, time.Now().Add(-time.Hour), time.Now(), 100, "backward")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(out.Logs))
	}

	line := out.Logs[0].Line
	if !utf8.ValidString(line) {
		t.Errorf("truncated line is not valid UTF-8: %q", line[:50])
	}
}

func TestBuildQueryLogsOutput_UsesAnalyzeLogs(t *testing.T) {
	// Verify that buildQueryLogsOutput calls AnalyzeLogs for pattern analysis
	ts1 := fmt.Sprintf("%d", time.Now().Add(-3*time.Second).UnixNano())
	ts2 := fmt.Sprintf("%d", time.Now().Add(-2*time.Second).UnixNano())
	ts3 := fmt.Sprintf("%d", time.Now().Add(-1*time.Second).UnixNano())

	resp := &QueryResponse{
		Data: QueryData{
			ResultType: "streams",
		},
	}
	streams := []Stream{
		{
			Labels: map[string]string{"service": "payments"},
			Values: [][]string{
				{ts1, "connection timeout"},
				{ts2, "connection timeout"},
				{ts3, "rate limit exceeded"},
			},
		},
	}
	streamJSON, _ := json.Marshal(streams)
	resp.Data.Result = streamJSON

	out, err := buildQueryLogsOutput(resp, `{service="payments"}`, time.Now().Add(-time.Hour), time.Now(), 100, "backward")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have patterns from AnalyzeLogs
	if out.TotalLogs != 3 {
		t.Errorf("expected TotalLogs=3, got %d", out.TotalLogs)
	}
	if len(out.TopPatterns) == 0 {
		t.Error("expected patterns to be populated by AnalyzeLogs")
	}
}

func TestBuildQueryStatsOutput_UsesAnalyzeStats(t *testing.T) {
	// Build a matrix response using raw JSON (SamplePair is [timestamp, "value"] wire format)
	now := time.Now()
	matrixJSON := fmt.Sprintf(`[{"metric":{"service":"payments"},"values":[[%d,"10"],[%d,"15"],[%d,"25"]]}]`,
		now.Add(-10*time.Minute).Unix(),
		now.Add(-5*time.Minute).Unix(),
		now.Unix(),
	)

	resp := &QueryResponse{
		Data: QueryData{
			ResultType: "matrix",
			Result:     json.RawMessage(matrixJSON),
		},
	}

	out, err := buildQueryStatsOutput(resp, `count_over_time({service="payments"}[5m])`, now.Add(-time.Hour), now, "5m")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.TotalSeries != 1 {
		t.Errorf("expected TotalSeries=1, got %d", out.TotalSeries)
	}
	if len(out.Summaries) != 1 {
		t.Errorf("expected 1 summary from AnalyzeStats, got %d", len(out.Summaries))
	}

	_ = QueryLogsOutput{}
}
