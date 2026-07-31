package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
)

// ---- input/output types ----

type ListMetricsInput struct {
	Match     string `json:"match,omitempty" jsonschema_description:"Optional series selector to filter metric names, e.g. {job=\"node\"}"`
	StartTime string `json:"start_time,omitempty" jsonschema_description:"Start time. Defaults to 6h ago"`
	EndTime   string `json:"end_time,omitempty" jsonschema_description:"End time. Defaults to now"`
}
type ListMetricsOutput struct {
	Metrics []string `json:"metrics"`
}

type GetMetricMetadataInput struct {
	Metric string `json:"metric,omitempty" jsonschema_description:"Metric name to describe. Empty returns metadata for all metrics."`
}
type GetMetricMetadataOutput struct {
	Metadata map[string][]MetadataEntry `json:"metadata"`
}

type GetMetricLabelValuesInput struct {
	LabelName string `json:"label_name" jsonschema_description:"Label to get values for, e.g. instance, job, service"`
	Match     string `json:"match,omitempty" jsonschema_description:"Optional series selector to scope values"`
	StartTime string `json:"start_time,omitempty" jsonschema_description:"Start time. Defaults to 6h ago"`
	EndTime   string `json:"end_time,omitempty" jsonschema_description:"End time. Defaults to now"`
}
type GetMetricLabelValuesOutput struct {
	LabelName string   `json:"label_name"`
	Values    []string `json:"values"`
}

type QueryInstantInput struct {
	PromQL string `json:"promql" jsonschema_description:"PromQL instant query, e.g. sum(rate(http_requests_total[5m]))"`
	Time   string `json:"time,omitempty" jsonschema_description:"Evaluation time — relative like 'now' or RFC3339. Defaults to now"`
}

type QueryRangeInput struct {
	PromQL    string `json:"promql" jsonschema_description:"PromQL range query, e.g. rate(http_requests_total[5m])"`
	StartTime string `json:"start_time" jsonschema_description:"Start time — PREFER relative like '1h ago', '2h ago'"`
	EndTime   string `json:"end_time,omitempty" jsonschema_description:"End time — 'now' or RFC3339. Defaults to now"`
	Step      string `json:"step,omitempty" jsonschema_description:"Resolution step (e.g. 30s, 1m). Auto-selected and bounded if empty."`
}

// ---- handlers ----

type ToolHandlers struct {
	client    Client
	validator *Validator
	audit     *audit.Logger
}

func NewToolHandlers(client Client, validator *Validator, auditLogger *audit.Logger) *ToolHandlers {
	return &ToolHandlers{client: client, validator: validator, audit: auditLogger}
}

func (h *ToolHandlers) ListMetrics(ctx context.Context, in ListMetricsInput) (ListMetricsOutput, error) {
	start := time.Now()
	st, err := loki.ParseTimeOrDefault(in.StartTime, 6*time.Hour)
	if err != nil {
		h.audit.ToolFailed("list_metrics", time.Since(start).Milliseconds(), err)
		return ListMetricsOutput{}, err
	}
	et, err := loki.ParseTimeOrDefault(in.EndTime, 0)
	if err != nil {
		h.audit.ToolFailed("list_metrics", time.Since(start).Milliseconds(), err)
		return ListMetricsOutput{}, err
	}
	resp, err := h.client.LabelValues(ctx, LabelValuesRequest{LabelName: "__name__", Start: st, End: et, Match: in.Match})
	if err != nil {
		h.audit.ToolFailed("list_metrics", time.Since(start).Milliseconds(), err)
		return ListMetricsOutput{}, fmt.Errorf("prometheus list_metrics failed: %w", err)
	}
	h.audit.ToolInvoked("list_metrics", time.Since(start).Milliseconds(), slog.Int("result_count", len(resp.Data)))
	return ListMetricsOutput{Metrics: resp.Data}, nil
}

func (h *ToolHandlers) GetMetricMetadata(ctx context.Context, in GetMetricMetadataInput) (GetMetricMetadataOutput, error) {
	start := time.Now()
	resp, err := h.client.Metadata(ctx, MetadataRequest{Metric: in.Metric})
	if err != nil {
		h.audit.ToolFailed("get_metric_metadata", time.Since(start).Milliseconds(), err)
		return GetMetricMetadataOutput{}, fmt.Errorf("prometheus metadata failed: %w", err)
	}
	h.audit.ToolInvoked("get_metric_metadata", time.Since(start).Milliseconds(), slog.Int("result_count", len(resp.Data)))
	return GetMetricMetadataOutput{Metadata: resp.Data}, nil
}

func (h *ToolHandlers) GetMetricLabelValues(ctx context.Context, in GetMetricLabelValuesInput) (GetMetricLabelValuesOutput, error) {
	start := time.Now()
	if in.LabelName == "" {
		err := fmt.Errorf("label_name is required")
		h.audit.ToolFailed("get_metric_label_values", time.Since(start).Milliseconds(), err)
		return GetMetricLabelValuesOutput{}, err
	}
	st, err := loki.ParseTimeOrDefault(in.StartTime, 6*time.Hour)
	if err != nil {
		return GetMetricLabelValuesOutput{}, err
	}
	et, err := loki.ParseTimeOrDefault(in.EndTime, 0)
	if err != nil {
		return GetMetricLabelValuesOutput{}, err
	}
	resp, err := h.client.LabelValues(ctx, LabelValuesRequest{LabelName: in.LabelName, Start: st, End: et, Match: in.Match})
	if err != nil {
		h.audit.ToolFailed("get_metric_label_values", time.Since(start).Milliseconds(), err)
		return GetMetricLabelValuesOutput{}, fmt.Errorf("prometheus label_values failed: %w", err)
	}
	h.audit.ToolInvoked("get_metric_label_values", time.Since(start).Milliseconds(), slog.String("label", in.LabelName), slog.Int("result_count", len(resp.Data)))
	return GetMetricLabelValuesOutput{LabelName: in.LabelName, Values: resp.Data}, nil
}

func (h *ToolHandlers) QueryInstant(ctx context.Context, in QueryInstantInput) (loki.QueryStatsOutput, error) {
	start := time.Now()
	out := loki.QueryStatsOutput{Query: in.PromQL, Series: []loki.MetricSeries{}}
	if in.PromQL == "" {
		err := fmt.Errorf("promql is required")
		h.audit.ToolFailed("query_metrics_instant", time.Since(start).Milliseconds(), err)
		return out, err
	}
	evalTime, err := loki.ParseTimeOrDefault(in.Time, 0)
	if err != nil {
		return out, err
	}
	resp, err := h.client.Query(ctx, InstantQueryRequest{Query: in.PromQL, Time: evalTime})
	if err != nil {
		h.audit.ToolFailed("query_metrics_instant", time.Since(start).Milliseconds(), err)
		return out, fmt.Errorf("prometheus instant query failed: %w", err)
	}
	out, err = buildMetricsOutput(resp, in.PromQL, "")
	if err != nil {
		h.audit.ToolFailed("query_metrics_instant", time.Since(start).Milliseconds(), err)
		return out, err
	}
	out.ExecTimeMS = int(time.Since(start).Milliseconds())
	h.audit.ToolInvoked("query_metrics_instant", time.Since(start).Milliseconds(), slog.String("query", in.PromQL), slog.Int("series_count", len(out.Series)))
	return out, nil
}

func (h *ToolHandlers) QueryRange(ctx context.Context, in QueryRangeInput) (loki.QueryStatsOutput, error) {
	start := time.Now()
	out := loki.QueryStatsOutput{Query: in.PromQL, Series: []loki.MetricSeries{}}
	if in.PromQL == "" {
		err := fmt.Errorf("promql is required")
		h.audit.ToolFailed("query_metrics_range", time.Since(start).Milliseconds(), err)
		return out, err
	}
	st, err := loki.ParseTimeOrDefault(in.StartTime, 1*time.Hour)
	if err != nil {
		return out, err
	}
	et, err := loki.ParseTimeOrDefault(in.EndTime, 0)
	if err != nil {
		return out, err
	}
	st, et, warn := h.validator.CapRange(st, et)
	step := h.validator.ResolveStep(st, et, in.Step)

	resp, err := h.client.QueryRange(ctx, QueryRangeRequest{Query: in.PromQL, Start: st, End: et, Step: step})
	if err != nil {
		h.audit.ToolFailed("query_metrics_range", time.Since(start).Milliseconds(), err)
		return out, fmt.Errorf("prometheus range query failed: %w", err)
	}
	out, err = buildMetricsOutput(resp, in.PromQL, step)
	if err != nil {
		h.audit.ToolFailed("query_metrics_range", time.Since(start).Milliseconds(), err)
		return out, err
	}
	if warn != "" {
		out.Warning = warn
	}
	out.ExecTimeMS = int(time.Since(start).Milliseconds())
	h.audit.ToolInvoked("query_metrics_range", time.Since(start).Milliseconds(), slog.String("query", in.PromQL), slog.Int("series_count", len(out.Series)))
	return out, nil
}

// buildMetricsOutput converts a Prometheus matrix/vector response into the
// shared loki.QueryStatsOutput and runs the shared trend summarizer.
func buildMetricsOutput(resp *loki.QueryResponse, query, step string) (loki.QueryStatsOutput, error) {
	out := loki.QueryStatsOutput{Query: query, Step: step, Series: []loki.MetricSeries{}}
	switch resp.Data.ResultType {
	case "matrix":
		var series []loki.MatrixSeries
		if err := json.Unmarshal(resp.Data.Result, &series); err != nil {
			return out, fmt.Errorf("parsing matrix: %w", err)
		}
		for _, s := range series {
			ms := loki.MetricSeries{Labels: s.Metric}
			for _, v := range s.Values {
				ts := time.Unix(int64(v.Timestamp), 0)
				ms.Values = append(ms.Values, loki.DataPoint{Timestamp: ts.Format(time.RFC3339), Value: v.Value})
			}
			out.Series = append(out.Series, ms)
		}
	case "vector":
		var samples []loki.VectorSample
		if err := json.Unmarshal(resp.Data.Result, &samples); err != nil {
			return out, fmt.Errorf("parsing vector: %w", err)
		}
		for _, s := range samples {
			ms := loki.MetricSeries{Labels: s.Metric}
			ts := time.Unix(int64(s.Value.Timestamp), 0)
			ms.Values = append(ms.Values, loki.DataPoint{Timestamp: ts.Format(time.RFC3339), Value: s.Value.Value})
			out.Series = append(out.Series, ms)
		}
	}
	loki.AnalyzeStats(&out)
	return out, nil
}
