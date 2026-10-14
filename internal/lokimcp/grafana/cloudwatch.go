package grafana

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
)

const (
	defaultDimensionValues = 100
	maxDimensionValues     = 1000
	maxCloudWatchSeries    = 20
)

var cloudWatchStats = map[string]string{
	"average": "Average", "avg": "Average", "sum": "Sum", "maximum": "Maximum", "max": "Maximum",
	"minimum": "Minimum", "min": "Minimum", "samplecount": "SampleCount", "count": "SampleCount",
}

type ListMetricsInput struct {
	Namespace string
	Region    string
}

type ListMetricsOutput struct {
	Namespace  string   `json:"namespace,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Metrics    []string `json:"metrics,omitempty"`
}

type DimensionsInput struct {
	Namespace string
	Metric    string
	Key       string
	Region    string
	Limit     int
}

type DimensionsOutput struct {
	Namespace string   `json:"namespace"`
	Metric    string   `json:"metric"`
	Key       string   `json:"key,omitempty"`
	Keys      []string `json:"keys,omitempty"`
	Values    []string `json:"values,omitempty"`
	Total     int      `json:"total,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

type CloudWatchQueryInput struct {
	Namespace  string
	Metric     string
	Dimensions map[string]string
	Statistic  string
	Period     int
	StartTime  string
	EndTime    string
	Region     string
}

type valueItem struct {
	Value any `json:"value"`
}

func (h *ToolHandlers) ListCloudWatchMetrics(ctx context.Context, in ListMetricsInput) (ListMetricsOutput, error) {
	start := time.Now()
	out := ListMetricsOutput{Namespace: in.Namespace}
	params := url.Values{"region": {regionOrDefault(in.Region)}}
	if in.Namespace == "" {
		var items []valueItem
		if err := h.client.Resource(ctx, h.cloudWatchUID, "namespaces", params, &items); err != nil {
			return out, h.fail("list_cloudwatch_metrics", start, fmt.Errorf("listing namespaces: %w", err))
		}
		out.Namespaces = valueStrings(items)
		h.audit.ToolInvoked("list_cloudwatch_metrics", time.Since(start).Milliseconds(), slog.Int("result_count", len(out.Namespaces)))
		return out, nil
	}
	params.Set("namespace", in.Namespace)
	var items []struct {
		Value struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := h.client.Resource(ctx, h.cloudWatchUID, "metrics", params, &items); err != nil {
		return out, h.fail("list_cloudwatch_metrics", start, fmt.Errorf("listing metrics: %w", err))
	}
	for _, it := range items {
		out.Metrics = append(out.Metrics, it.Value.Name)
	}
	sort.Strings(out.Metrics)
	h.audit.ToolInvoked("list_cloudwatch_metrics", time.Since(start).Milliseconds(), slog.String("namespace", in.Namespace), slog.Int("result_count", len(out.Metrics)))
	return out, nil
}

func (h *ToolHandlers) GetCloudWatchDimensions(ctx context.Context, in DimensionsInput) (DimensionsOutput, error) {
	start := time.Now()
	out := DimensionsOutput{Namespace: in.Namespace, Metric: in.Metric, Key: in.Key}
	if in.Namespace == "" || in.Metric == "" {
		return out, h.fail("get_cloudwatch_dimensions", start, fmt.Errorf("namespace and metric are required"))
	}
	params := url.Values{"region": {regionOrDefault(in.Region)}, "namespace": {in.Namespace}, "metricName": {in.Metric}}
	path := "dimension-keys"
	if in.Key != "" {
		path = "dimension-values"
		params.Set("dimensionKey", in.Key)
	}
	var items []valueItem
	if err := h.client.Resource(ctx, h.cloudWatchUID, path, params, &items); err != nil {
		return out, h.fail("get_cloudwatch_dimensions", start, fmt.Errorf("listing dimensions: %w", err))
	}
	vals := valueStrings(items)
	if in.Key == "" {
		out.Keys = vals
	} else {
		out.Total = len(vals)
		if limit := clamp(in.Limit, defaultDimensionValues, maxDimensionValues); len(vals) > limit {
			vals = vals[:limit]
			out.Truncated = true
		}
		out.Values = vals
	}
	h.audit.ToolInvoked("get_cloudwatch_dimensions", time.Since(start).Milliseconds(), slog.String("metric", in.Metric), slog.Int("result_count", len(vals)))
	return out, nil
}

func (h *ToolHandlers) QueryCloudWatch(ctx context.Context, in CloudWatchQueryInput) (loki.QueryStatsOutput, error) {
	start := time.Now()
	out := loki.QueryStatsOutput{Series: []loki.MetricSeries{}}
	if in.Namespace == "" || in.Metric == "" {
		return out, h.fail("query_cloudwatch", start, fmt.Errorf("namespace and metric are required"))
	}
	stat, err := normalizeStatistic(in.Statistic)
	if err != nil {
		return out, h.fail("query_cloudwatch", start, err)
	}
	st, et, warn, err := resolveRange(in.StartTime, in.EndTime, time.Hour, h.cloudWatchMaxRange)
	if err != nil {
		return out, h.fail("query_cloudwatch", start, err)
	}
	period := resolvePeriod(st, et, in.Period, h.cloudWatchMaxPoints)
	dims := map[string][]string{}
	for k, v := range in.Dimensions {
		dims[k] = []string{v}
	}
	out.Query = fmt.Sprintf("%s %s %s %v period=%ds", in.Namespace, in.Metric, stat, in.Dimensions, period)
	out.Step = fmt.Sprintf("%ds", period)
	out.Warning = warn
	resp, err := h.client.Query(ctx, QueryRequest{From: st, To: et, Queries: []map[string]any{{
		"refId":      "A",
		"datasource": map[string]string{"uid": h.cloudWatchUID},
		"queryMode":  "Metrics",
		"region":     regionOrDefault(in.Region),
		"namespace":  in.Namespace,
		"metricName": in.Metric,
		"dimensions": dims,
		"statistic":  stat,
		"period":     strconv.Itoa(period),
		"matchExact": true,
	}}})
	if err != nil {
		return out, h.fail("query_cloudwatch", start, fmt.Errorf("cloudwatch query failed: %w", err))
	}
	res, err := resp.Single("A")
	if err != nil {
		return out, h.fail("query_cloudwatch", start, fmt.Errorf("cloudwatch query failed: %w", err))
	}
	out.Series = framesToSeries(res.Frames)
	if len(out.Series) > maxCloudWatchSeries {
		out.Warning = joinWarning(out.Warning, fmt.Sprintf("%d series matched; showing the first %d — narrow the dimensions", len(out.Series), maxCloudWatchSeries))
		out.Series = out.Series[:maxCloudWatchSeries]
	}
	if len(out.Series) == 0 {
		out.Note = "no datapoints: check dimension names/values with get_cloudwatch_dimensions; count metrics (e.g. HTTPCode_ELB_5XX_Count) publish nothing while zero"
	}
	loki.AnalyzeStats(&out)
	out.ExecTimeMS = int(time.Since(start).Milliseconds())
	h.audit.ToolInvoked("query_cloudwatch", time.Since(start).Milliseconds(), slog.String("metric", in.Metric), slog.Int("series_count", len(out.Series)))
	return out, nil
}

func framesToSeries(frames []Frame) []loki.MetricSeries {
	series := []loki.MetricSeries{}
	for _, f := range frames {
		for fi := 1; fi < len(f.Schema.Fields) && fi < len(f.Data.Values); fi++ {
			labels := map[string]string{}
			for k, v := range f.Schema.Fields[fi].Labels {
				if k != "Series" {
					labels[k] = v
				}
			}
			if len(labels) == 0 && f.Schema.Name != "" {
				labels["series"] = f.Schema.Name
			}
			ms := loki.MetricSeries{Labels: labels}
			for r := 0; r < f.RowCount(); r++ {
				v, ok := f.Data.Values[fi][r].(float64)
				if !ok {
					continue
				}
				ts, _ := f.Data.Values[0][r].(float64)
				ms.Values = append(ms.Values, loki.DataPoint{
					Timestamp: time.UnixMilli(int64(ts)).UTC().Format(time.RFC3339),
					Value:     strconv.FormatFloat(v, 'f', -1, 64),
				})
			}
			if len(ms.Values) > 0 {
				series = append(series, ms)
			}
		}
	}
	return series
}

func normalizeStatistic(s string) (string, error) {
	if s == "" {
		return "Average", nil
	}
	if v, ok := cloudWatchStats[strings.ToLower(s)]; ok {
		return v, nil
	}
	if l := strings.ToLower(s); len(l) > 1 && l[0] == 'p' {
		if _, err := strconv.ParseFloat(l[1:], 64); err == nil {
			return l, nil
		}
	}
	return "", fmt.Errorf("unsupported statistic %q; use Average, Sum, Maximum, Minimum, SampleCount or a percentile like p99", s)
}

func resolvePeriod(start, end time.Time, requested, maxPoints int) int {
	period := requested
	if period <= 0 {
		period = 60
	}
	if maxPoints > 0 {
		minPeriod := int(math.Ceil(math.Floor(end.Sub(start).Seconds()) / float64(maxPoints)))
		if period < minPeriod {
			period = minPeriod
		}
	}
	if period < 60 {
		period = 60
	}
	return int(math.Ceil(float64(period)/60)) * 60
}

func regionOrDefault(r string) string {
	if r == "" {
		return "default"
	}
	return r
}

func valueStrings(items []valueItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.Value.(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
