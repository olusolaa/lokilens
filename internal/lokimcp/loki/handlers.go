package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/safety"
)

// Loki-specific tool input types

type QueryLogsInput struct {
	LogQL     string `json:"logql" jsonschema_description:"LogQL query string with stream selector and optional filters"`
	StartTime string `json:"start_time" jsonschema_description:"Start time — PREFER relative like '10m ago', '2h ago', '1d ago'. RFC3339 only if user gives a specific date/time. Defaults to 1h ago"`
	EndTime   string `json:"end_time,omitempty" jsonschema_description:"End time — PREFER relative like 'now' or '1h ago'. Defaults to now"`
	Limit     int    `json:"limit,omitempty" jsonschema_description:"Max log lines to return. Default 100 and max 500"`
	Direction string `json:"direction,omitempty" jsonschema_description:"Sort order: backward (newest first) or forward (oldest first). Default backward"`
}

type GetLabelsInput struct {
	StartTime string `json:"start_time,omitempty" jsonschema_description:"Start time. Defaults to 6h ago"`
	EndTime   string `json:"end_time,omitempty" jsonschema_description:"End time. Defaults to now"`
}

type GetLabelsOutput struct {
	Labels []string `json:"labels"`
}

type GetLabelValuesInput struct {
	LabelName string `json:"label_name" jsonschema_description:"The label to get values for (e.g. service or level)"`
	StartTime string `json:"start_time,omitempty" jsonschema_description:"Start time. Defaults to 6h ago"`
	EndTime   string `json:"end_time,omitempty" jsonschema_description:"End time. Defaults to now"`
}

type GetLabelValuesOutput struct {
	LabelName string   `json:"label_name"`
	Values    []string `json:"values"`
}

type QueryStatsInput struct {
	LogQL     string `json:"logql" jsonschema_description:"LogQL metric query for aggregated statistics"`
	StartTime string `json:"start_time" jsonschema_description:"Start time — PREFER relative like '10m ago', '2h ago', '1d ago'. RFC3339 only if user gives a specific date/time"`
	EndTime   string `json:"end_time,omitempty" jsonschema_description:"End time — PREFER relative like 'now'. Defaults to now"`
	Step      string `json:"step,omitempty" jsonschema_description:"Query resolution step (e.g. 1m or 5m). Leave empty to auto-select based on time range (30s for ≤30m, 1m for ≤2h, 5m for ≤6h, 15m for ≤12h, 1h for 24h)"`
}

// ToolHandlers holds the tool handler functions bound to a Loki client and validator.
type ToolHandlers struct {
	lokiClient Client
	validator  *safety.Validator
	audit      *audit.Logger
}

// NewToolHandlers creates tool handlers with the given dependencies.
func NewToolHandlers(lokiClient Client, validator *safety.Validator, auditLogger *audit.Logger) *ToolHandlers {
	return &ToolHandlers{
		lokiClient: lokiClient,
		validator:  validator,
		audit:      auditLogger,
	}
}

func (h *ToolHandlers) QueryLogs(ctx context.Context, input QueryLogsInput) (QueryLogsOutput, error) {
	start := time.Now()

	input.LogQL = safety.SanitizeQuery(input.LogQL)
	if err := h.validator.ValidateQuery(input.LogQL, input.StartTime, input.EndTime); err != nil {
		h.audit.ToolFailed("query_logs", time.Since(start).Milliseconds(), err)
		return QueryLogsOutput{}, fmt.Errorf("validation failed: %w", err)
	}

	startTime, err := ParseTimeOrDefault(input.StartTime, 1*time.Hour)
	if err != nil {
		h.audit.ToolFailed("query_logs", time.Since(start).Milliseconds(), err)
		return QueryLogsOutput{}, err
	}
	endTime, err := ParseTimeOrDefault(input.EndTime, 0)
	if err != nil {
		h.audit.ToolFailed("query_logs", time.Since(start).Milliseconds(), err)
		return QueryLogsOutput{}, err
	}

	var warning string
	startTime, endTime, warning = sanitizeTimeRange(startTime, endTime)

	limit := clamp(input.Limit, 1, h.validator.MaxResults())
	if input.Limit == 0 {
		limit = 100
	}

	direction := input.Direction
	if direction == "" {
		direction = "backward"
	}
	if direction != "forward" && direction != "backward" {
		direction = "backward"
	}

	resp, err := h.lokiClient.QueryRange(ctx, QueryRangeRequest{
		Query:     input.LogQL,
		Start:     startTime,
		End:       endTime,
		Limit:     limit,
		Direction: direction,
	})
	if err != nil {
		h.audit.ToolFailed("query_logs", time.Since(start).Milliseconds(), err)
		return QueryLogsOutput{}, fmt.Errorf("loki query failed: %w", err)
	}

	// Auto-widen: only when no explicit start time was given and zero results.
	usedStart := startTime
	if lokiResponseEmpty(resp) && strings.TrimSpace(input.StartTime) == "" {
		widenResult, widenErr := AutoWiden(ctx, AutoWidenConfig{
			EndTime:      endTime,
			InitialStart: startTime,
			Query:        input.LogQL,
			MaxRange:     maxLokiQueryRange,
		}, func(wStart, wEnd time.Time) (bool, error) {
			resp, err = h.lokiClient.QueryRange(ctx, QueryRangeRequest{
				Query:     input.LogQL,
				Start:     wStart,
				End:       wEnd,
				Limit:     limit,
				Direction: direction,
			})
			if err != nil {
				return false, err
			}
			return lokiResponseEmpty(resp), nil
		})
		if widenErr != nil {
			h.audit.ToolFailed("query_logs", time.Since(start).Milliseconds(), widenErr)
			return QueryLogsOutput{}, fmt.Errorf("loki query failed: %w", widenErr)
		}
		usedStart = widenResult.UsedStart
		if widenResult.Warning != "" {
			if warning != "" {
				warning += "; " + widenResult.Warning
			} else {
				warning = widenResult.Warning
			}
		}
	}

	out, err := buildQueryLogsOutput(resp, input.LogQL, usedStart, endTime, limit, direction)
	if err != nil {
		h.audit.ToolFailed("query_logs", time.Since(start).Milliseconds(), err)
		return out, err
	}

	// Zero-results warning: different messages depending on whether auto-widening ran
	if len(out.Logs) == 0 {
		var hints string
		if strings.TrimSpace(input.StartTime) == "" {
			hints = "Searched up to 90 days back with auto-widening and found nothing. " +
				"Possible causes: (1) label names/values are wrong — call get_labels and get_label_values to verify, " +
				"(2) the filter is too specific — try removing line filters, " +
				"(3) the service may not be logging."
		} else {
			hints = "⚠️ MANDATORY: Do NOT respond to the user yet. You MUST retry at least 2 of these before saying anything about no logs: " +
				"(1) widen time range to 6h or 24h, (2) remove filters (use a bare selector like {service=~\".+\"}), " +
				"(3) call get_labels to verify label names/values exist, (4) check for typos in label values. " +
				"Only after 2+ retries with zero results should you tell the user — and if truly empty, say it's suspicious (possible logging gap or service down), not 'no activity'."
		}
		if out.Warning != "" {
			out.Warning += " | " + hints
		} else {
			out.Warning = hints
		}
	}

	if warning != "" {
		if out.Warning != "" {
			out.Warning = warning + " | " + out.Warning
		} else {
			out.Warning = warning
		}
	}
	out.ExecTimeMS = int(time.Since(start).Milliseconds())

	h.audit.ToolInvoked("query_logs", time.Since(start).Milliseconds(),
		slog.String("query", input.LogQL),
		slog.Int("result_count", out.TotalLogs),
	)
	return out, nil
}

func (h *ToolHandlers) GetLabels(ctx context.Context, input GetLabelsInput) (GetLabelsOutput, error) {
	start := time.Now()

	startTime, err := ParseTimeOrDefault(input.StartTime, 6*time.Hour)
	if err != nil {
		h.audit.ToolFailed("get_labels", time.Since(start).Milliseconds(), err)
		return GetLabelsOutput{}, err
	}
	endTime, err := ParseTimeOrDefault(input.EndTime, 0)
	if err != nil {
		h.audit.ToolFailed("get_labels", time.Since(start).Milliseconds(), err)
		return GetLabelsOutput{}, err
	}

	resp, err := h.lokiClient.Labels(ctx, LabelsRequest{
		Start: startTime,
		End:   endTime,
	})
	if err != nil {
		h.audit.ToolFailed("get_labels", time.Since(start).Milliseconds(), err)
		return GetLabelsOutput{}, fmt.Errorf("loki labels failed: %w", err)
	}

	h.audit.ToolInvoked("get_labels", time.Since(start).Milliseconds(),
		slog.Int("result_count", len(resp.Data)),
	)
	return GetLabelsOutput{Labels: resp.Data}, nil
}

func (h *ToolHandlers) GetLabelValues(ctx context.Context, input GetLabelValuesInput) (GetLabelValuesOutput, error) {
	start := time.Now()

	if input.LabelName == "" {
		err := fmt.Errorf("label_name is required")
		h.audit.ToolFailed("get_label_values", time.Since(start).Milliseconds(), err)
		return GetLabelValuesOutput{}, err
	}

	startTime, err := ParseTimeOrDefault(input.StartTime, 6*time.Hour)
	if err != nil {
		h.audit.ToolFailed("get_label_values", time.Since(start).Milliseconds(), err)
		return GetLabelValuesOutput{}, err
	}
	endTime, err := ParseTimeOrDefault(input.EndTime, 0)
	if err != nil {
		h.audit.ToolFailed("get_label_values", time.Since(start).Milliseconds(), err)
		return GetLabelValuesOutput{}, err
	}

	resp, err := h.lokiClient.LabelValues(ctx, LabelValuesRequest{
		LabelName: input.LabelName,
		Start:     startTime,
		End:       endTime,
	})
	if err != nil {
		h.audit.ToolFailed("get_label_values", time.Since(start).Milliseconds(), err)
		return GetLabelValuesOutput{}, fmt.Errorf("loki label_values failed: %w", err)
	}

	h.audit.ToolInvoked("get_label_values", time.Since(start).Milliseconds(),
		slog.String("label", input.LabelName),
		slog.Int("result_count", len(resp.Data)),
	)
	return GetLabelValuesOutput{
		LabelName: input.LabelName,
		Values:    resp.Data,
	}, nil
}

func (h *ToolHandlers) QueryStats(ctx context.Context, input QueryStatsInput) (QueryStatsOutput, error) {
	start := time.Now()

	input.LogQL = safety.SanitizeQuery(input.LogQL)
	if err := h.validator.ValidateQuery(input.LogQL, input.StartTime, input.EndTime); err != nil {
		h.audit.ToolFailed("query_stats", time.Since(start).Milliseconds(), err)
		return QueryStatsOutput{}, fmt.Errorf("validation failed: %w", err)
	}

	startTime, err := ParseTimeOrDefault(input.StartTime, 1*time.Hour)
	if err != nil {
		h.audit.ToolFailed("query_stats", time.Since(start).Milliseconds(), err)
		return QueryStatsOutput{}, err
	}
	endTime, err := ParseTimeOrDefault(input.EndTime, 0)
	if err != nil {
		h.audit.ToolFailed("query_stats", time.Since(start).Milliseconds(), err)
		return QueryStatsOutput{}, err
	}

	var warning string
	startTime, endTime, warning = sanitizeTimeRange(startTime, endTime)

	queryStep := input.Step
	if queryStep == "" {
		queryStep = AutoSelectStep(startTime, endTime)
	}

	resp, err := h.lokiClient.QueryRange(ctx, QueryRangeRequest{
		Query: input.LogQL,
		Start: startTime,
		End:   endTime,
		Step:  queryStep,
	})
	if err != nil {
		h.audit.ToolFailed("query_stats", time.Since(start).Milliseconds(), err)
		return QueryStatsOutput{}, fmt.Errorf("loki metric query failed: %w", err)
	}

	// Auto-widen: only when no explicit start time was given and zero results.
	usedStart := startTime
	if lokiResponseEmpty(resp) && strings.TrimSpace(input.StartTime) == "" {
		widenResult, widenErr := AutoWiden(ctx, AutoWidenConfig{
			EndTime:      endTime,
			InitialStart: startTime,
			Query:        input.LogQL,
			MaxRange:     maxLokiQueryRange,
		}, func(wStart, wEnd time.Time) (bool, error) {
			if input.Step == "" {
				queryStep = AutoSelectStep(wStart, wEnd)
			}
			resp, err = h.lokiClient.QueryRange(ctx, QueryRangeRequest{
				Query: input.LogQL,
				Start: wStart,
				End:   wEnd,
				Step:  queryStep,
			})
			if err != nil {
				return false, err
			}
			return lokiResponseEmpty(resp), nil
		})
		if widenErr != nil {
			h.audit.ToolFailed("query_stats", time.Since(start).Milliseconds(), widenErr)
			return QueryStatsOutput{}, fmt.Errorf("loki metric query failed: %w", widenErr)
		}
		usedStart = widenResult.UsedStart
		if widenResult.Warning != "" {
			if warning != "" {
				warning += "; " + widenResult.Warning
			} else {
				warning = widenResult.Warning
			}
		}
	}

	finalStep := input.Step
	if finalStep == "" {
		finalStep = AutoSelectStep(usedStart, endTime)
	}

	out, err := buildQueryStatsOutput(resp, input.LogQL, usedStart, endTime, finalStep)
	if err != nil {
		h.audit.ToolFailed("query_stats", time.Since(start).Milliseconds(), err)
		return out, err
	}

	// Zero-results warning: different messages depending on whether auto-widening ran
	if len(out.Series) == 0 {
		var hints string
		if strings.TrimSpace(input.StartTime) == "" {
			hints = "Searched up to 90 days back with auto-widening and found nothing. " +
				"Possible causes: (1) label names/values are wrong — call get_labels and get_label_values to verify, " +
				"(2) the query may be wrong — simplify it, " +
				"(3) the service may not be logging."
		} else {
			hints = "⚠️ MANDATORY: Do NOT respond to the user yet. You MUST retry at least 2 of these before saying anything about no logs: " +
				"(1) widen time range to 6h or 24h, (2) simplify the query, " +
				"(3) call get_labels to verify label names/values exist. " +
				"Only after 2+ retries with zero results should you tell the user — and if truly empty, say it's suspicious (possible logging gap or service down), not 'no activity'."
		}
		if out.Warning != "" {
			out.Warning += " | " + hints
		} else {
			out.Warning = hints
		}
	}

	if warning != "" {
		if out.Warning != "" {
			out.Warning = warning + " | " + out.Warning
		} else {
			out.Warning = warning
		}
	}
	out.ExecTimeMS = int(time.Since(start).Milliseconds())

	h.audit.ToolInvoked("query_stats", time.Since(start).Milliseconds(),
		slog.String("query", input.LogQL),
		slog.Int("series_count", len(out.Series)),
	)
	return out, nil
}

// maxLokiQueryRange is the maximum time range we send to Loki.
// Loki's hard limit is 30d1h; we cap at 30d to stay within it.
const maxLokiQueryRange = 30 * 24 * time.Hour

// sanitizeTimeRange swaps start/end if reversed, caps future end times,
// and enforces a maximum query range to prevent Loki 400 errors.
func sanitizeTimeRange(start, end time.Time) (time.Time, time.Time, string) {
	var warnings []string

	// Swap if reversed
	if end.Before(start) {
		start, end = end, start
		warnings = append(warnings, "start/end times were swapped")
	}

	// Cap future end times
	now := time.Now()
	if end.After(now) {
		end = now
	}

	// Ensure non-zero range
	if !end.After(start) {
		start = end.Add(-1 * time.Hour)
		warnings = append(warnings, "defaulted to 1h time range")
	}

	// Cap max range to Loki's limit (30d) — the model sometimes hallucinates
	// start times months in the past, causing Loki to reject with HTTP 400.
	if end.Sub(start) > maxLokiQueryRange {
		origStart := start
		start = end.Add(-maxLokiQueryRange)
		warnings = append(warnings, fmt.Sprintf("time range capped to 30 days (Loki limit); original start was %s", origStart.Format(time.RFC3339)))
	}

	return start, end, strings.Join(warnings, "; ")
}

func clamp(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

func buildQueryLogsOutput(resp *QueryResponse, query string, start, end time.Time, limit int, direction string) (QueryLogsOutput, error) {
	out := QueryLogsOutput{
		Query:     query,
		Direction: direction,
		Logs:      []LogEntry{},
		TimeRange: fmt.Sprintf("%s to %s", start.Format(time.RFC3339), end.Format(time.RFC3339)),
	}

	if resp.Data.ResultType != "streams" {
		return out, nil
	}

	var streams []Stream
	if err := json.Unmarshal(resp.Data.Result, &streams); err != nil {
		return out, fmt.Errorf("parsing streams: %w", err)
	}

	for _, s := range streams {
		for _, v := range s.Values {
			if len(v) < 2 {
				continue
			}
			ts, err := ParseNanoTimestamp(v[0])
			if err != nil {
				continue
			}
			out.Logs = append(out.Logs, LogEntry{
				Timestamp: ts.Format("2006-01-02T15:04:05.000Z07:00"),
				Line:      TruncateLogLine(v[1]),
				Labels:    s.Labels,
			})
		}
	}

	// Use shared analysis for sorting, patterns, and label distribution
	AnalyzeLogs(&out, limit)

	return out, nil
}

// lokiResponseEmpty checks if a Loki query response has zero results by
// parsing the result rather than string-matching raw JSON.
func lokiResponseEmpty(resp *QueryResponse) bool {
	if resp == nil {
		return true
	}
	raw := resp.Data.Result
	if len(raw) == 0 {
		return true
	}

	switch resp.Data.ResultType {
	case "streams":
		var streams []Stream
		if err := json.Unmarshal(raw, &streams); err != nil {
			return true // can't parse → treat as empty
		}
		for _, s := range streams {
			if len(s.Values) > 0 {
				return false
			}
		}
		return true
	case "matrix":
		var series []MatrixSeries
		if err := json.Unmarshal(raw, &series); err != nil {
			return true
		}
		for _, s := range series {
			if len(s.Values) > 0 {
				return false
			}
		}
		return true
	case "vector":
		var samples []VectorSample
		if err := json.Unmarshal(raw, &samples); err != nil {
			return true
		}
		return len(samples) == 0
	default:
		// Unknown type — check if raw JSON is an empty array
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return true
		}
		return len(arr) == 0
	}
}

func buildQueryStatsOutput(resp *QueryResponse, query string, start, end time.Time, step string) (QueryStatsOutput, error) {
	out := QueryStatsOutput{
		Query:     query,
		Step:      step,
		Series:    []MetricSeries{},
		TimeRange: fmt.Sprintf("%s to %s", start.Format(time.RFC3339), end.Format(time.RFC3339)),
	}

	switch resp.Data.ResultType {
	case "matrix":
		var series []MatrixSeries
		if err := json.Unmarshal(resp.Data.Result, &series); err != nil {
			return out, fmt.Errorf("parsing matrix: %w", err)
		}
		for _, s := range series {
			ms := MetricSeries{Labels: s.Metric}
			for _, v := range s.Values {
				ts := time.Unix(int64(v.Timestamp), 0)
				ms.Values = append(ms.Values, DataPoint{
					Timestamp: ts.Format(time.RFC3339),
					Value:     v.Value,
				})
			}
			out.Series = append(out.Series, ms)
		}
	case "vector":
		var samples []VectorSample
		if err := json.Unmarshal(resp.Data.Result, &samples); err != nil {
			return out, fmt.Errorf("parsing vector: %w", err)
		}
		for _, s := range samples {
			ms := MetricSeries{Labels: s.Metric}
			ts := time.Unix(int64(s.Value.Timestamp), 0)
			ms.Values = append(ms.Values, DataPoint{
				Timestamp: ts.Format(time.RFC3339),
				Value:     s.Value.Value,
			})
			out.Series = append(out.Series, ms)
		}
	}

	// Use shared analysis for trend summaries and downsampling
	AnalyzeStats(&out)

	return out, nil
}
