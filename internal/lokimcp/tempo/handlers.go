package tempo

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
)

const (
	defaultSearchLimit    = 20
	maxSearchLimit        = 50
	spansPerTrace         = 3
	defaultMaxSpans       = 60
	maxMaxSpans           = 300
	defaultTagValuesLimit = 100
	maxTagValuesLimit     = 1000
	maxAttrValueLen       = 300
	maxErrorSpans         = 20
	traceOutputBudget     = 24_000
)

var sensitiveAttrFragments = []string{"connection_string", "password", "passwd", "secret", "token", "authorization", "cookie", "api_key", "apikey", "credential"}

type SearchTracesInput struct {
	TraceQL   string
	StartTime string
	EndTime   string
	Limit     int
}

type SearchTracesOutput struct {
	Query   string         `json:"query"`
	Traces  []TraceSummary `json:"traces"`
	Count   int            `json:"count"`
	Warning string         `json:"warning,omitempty"`
}

type TraceSummary struct {
	TraceID      string                  `json:"trace_id"`
	RootService  string                  `json:"root_service"`
	RootName     string                  `json:"root_name,omitempty"`
	Start        string                  `json:"start"`
	DurationMS   int64                   `json:"duration_ms"`
	Services     map[string]ServiceStats `json:"services,omitempty"`
	MatchedSpans []MatchedSpan           `json:"matched_spans,omitempty"`
}

type MatchedSpan struct {
	SpanID     string            `json:"span_id"`
	Name       string            `json:"name,omitempty"`
	DurationMS float64           `json:"duration_ms"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type GetTraceInput struct {
	TraceID       string
	Service       string
	MinDurationMS float64
	MaxSpans      int
	StartTime     string
	EndTime       string
}

type GetTraceOutput struct {
	TraceID    string           `json:"trace_id"`
	Start      string           `json:"start"`
	DurationMS float64          `json:"duration_ms"`
	TotalSpans int              `json:"total_spans"`
	ShownSpans int              `json:"shown_spans"`
	Services   []ServiceSummary `json:"services"`
	Errors     []Span           `json:"errors,omitempty"`
	Spans      []Span           `json:"spans"`
	Warning    string           `json:"warning,omitempty"`
}

type ServiceSummary struct {
	Name       string  `json:"name"`
	Spans      int     `json:"spans"`
	Errors     int     `json:"errors,omitempty"`
	SelfTimeMS float64 `json:"self_time_ms"`
}

type Span struct {
	SpanID        string            `json:"span_id"`
	ParentID      string            `json:"parent_id,omitempty"`
	Depth         int               `json:"depth"`
	Service       string            `json:"service"`
	Name          string            `json:"name"`
	Kind          string            `json:"kind,omitempty"`
	OffsetMS      float64           `json:"offset_ms"`
	DurationMS    float64           `json:"duration_ms"`
	SelfTimeMS    float64           `json:"self_time_ms"`
	Error         bool              `json:"error,omitempty"`
	StatusMessage string            `json:"status_message,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

type GetTraceTagsInput struct {
	Scope     string
	StartTime string
	EndTime   string
}

type GetTraceTagsOutput struct {
	Scopes map[string][]string `json:"scopes"`
}

type GetTraceTagValuesInput struct {
	Tag       string
	TraceQL   string
	StartTime string
	EndTime   string
	Limit     int
}

type GetTraceTagValuesOutput struct {
	Tag       string   `json:"tag"`
	Values    []string `json:"values"`
	Total     int      `json:"total"`
	Truncated bool     `json:"truncated,omitempty"`
}

type ToolHandlers struct {
	client   Client
	maxRange time.Duration
	audit    *audit.Logger
}

func NewToolHandlers(client Client, maxRange time.Duration, auditLogger *audit.Logger) *ToolHandlers {
	if maxRange <= 0 {
		maxRange = 24 * time.Hour
	}
	return &ToolHandlers{client: client, maxRange: maxRange, audit: auditLogger}
}

func (h *ToolHandlers) resolveRange(startIn, endIn string, defaultAgo time.Duration) (time.Time, time.Time, string, error) {
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
	if et.Sub(st) > h.maxRange {
		orig := st
		st = et.Add(-h.maxRange)
		return st, et, fmt.Sprintf("time range capped to %s (was from %s)", h.maxRange, orig.Format(time.RFC3339)), nil
	}
	return st, et, "", nil
}

func (h *ToolHandlers) fail(tool string, start time.Time, err error) error {
	h.audit.ToolFailed(tool, time.Since(start).Milliseconds(), err)
	return err
}

func (h *ToolHandlers) SearchTraces(ctx context.Context, in SearchTracesInput) (SearchTracesOutput, error) {
	start := time.Now()
	out := SearchTracesOutput{Query: in.TraceQL, Traces: []TraceSummary{}}
	if strings.TrimSpace(in.TraceQL) == "" {
		return out, h.fail("search_traces", start, fmt.Errorf("traceql is required, e.g. {resource.service.name=\"wallet-service\" && duration>1s}"))
	}
	st, et, warn, err := h.resolveRange(in.StartTime, in.EndTime, time.Hour)
	if err != nil {
		return out, h.fail("search_traces", start, err)
	}
	limit := clamp(in.Limit, defaultSearchLimit, maxSearchLimit)
	resp, err := h.client.Search(ctx, SearchRequest{Query: withSpanNames(in.TraceQL), Start: st, End: et, Limit: limit, SpansPerSpanSet: spansPerTrace})
	if err != nil {
		return out, h.fail("search_traces", start, fmt.Errorf("tempo search failed: %w", err))
	}
	for _, t := range resp.Traces {
		out.Traces = append(out.Traces, summarizeSearchTrace(t))
	}
	out.Count = len(out.Traces)
	out.Warning = warn
	if out.Count == limit {
		out.Warning = joinWarning(out.Warning, fmt.Sprintf("hit the limit of %d traces; narrow the TraceQL or time range for a complete picture", limit))
	}
	h.audit.ToolInvoked("search_traces", time.Since(start).Milliseconds(), slog.String("query", in.TraceQL), slog.Int("result_count", out.Count))
	return out, nil
}

func withSpanNames(q string) string {
	if strings.Contains(q, "select(") {
		return q
	}
	return strings.TrimSpace(q) + " | select(name)"
}

func summarizeSearchTrace(t SearchTrace) TraceSummary {
	s := TraceSummary{
		TraceID:     t.TraceID,
		RootService: t.RootServiceName,
		RootName:    t.RootTraceName,
		Start:       nanosToTime(t.StartTimeUnixNano).UTC().Format(time.RFC3339Nano),
		DurationMS:  t.DurationMs,
		Services:    t.ServiceStats,
	}
	for _, set := range t.SpanSets {
		for _, sp := range set.Spans {
			if len(s.MatchedSpans) >= spansPerTrace {
				break
			}
			attrs := attrMap(sp.Attributes)
			delete(attrs, "service.name")
			s.MatchedSpans = append(s.MatchedSpans, MatchedSpan{
				SpanID:     sp.SpanID,
				Name:       sp.Name,
				DurationMS: nanosStrToMS(sp.DurationNanos),
				Attributes: attrs,
			})
		}
	}
	return s
}

func (h *ToolHandlers) GetTrace(ctx context.Context, in GetTraceInput) (GetTraceOutput, error) {
	start := time.Now()
	out := GetTraceOutput{TraceID: in.TraceID, Spans: []Span{}}
	if strings.TrimSpace(in.TraceID) == "" {
		return out, h.fail("get_trace", start, fmt.Errorf("trace_id is required"))
	}
	req := TraceRequest{TraceID: strings.TrimSpace(in.TraceID)}
	if in.StartTime != "" || in.EndTime != "" {
		st, et, _, err := h.resolveRange(in.StartTime, in.EndTime, h.maxRange)
		if err != nil {
			return out, h.fail("get_trace", start, err)
		}
		req.Start, req.End = st, et
	}
	resp, err := h.client.Trace(ctx, req)
	if err != nil {
		return out, h.fail("get_trace", start, fmt.Errorf("tempo trace lookup failed: %w", err))
	}
	out = buildTraceOutput(req.TraceID, resp, in.Service, in.MinDurationMS, clamp(in.MaxSpans, defaultMaxSpans, maxMaxSpans))
	h.audit.ToolInvoked("get_trace", time.Since(start).Milliseconds(), slog.String("trace_id", req.TraceID), slog.Int("span_count", out.TotalSpans))
	return out, nil
}

type flatSpan struct {
	Span
	startNS int64
	endNS   int64
}

func buildTraceOutput(traceID string, resp *TraceResponse, service string, minDurationMS float64, maxSpans int) GetTraceOutput {
	out := GetTraceOutput{TraceID: traceID, Spans: []Span{}}
	var all []*flatSpan
	for _, rs := range resp.Trace.ResourceSpans {
		svc := attrMap(rs.Resource.Attributes)["service.name"]
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				fs := &flatSpan{
					Span: Span{
						SpanID:        otlpID(sp.SpanID),
						ParentID:      otlpID(sp.ParentSpanID),
						Service:       svc,
						Kind:          strings.ToLower(strings.TrimPrefix(sp.Kind, "SPAN_KIND_")),
						Error:         sp.Status.Code == "STATUS_CODE_ERROR",
						StatusMessage: truncate(sp.Status.Message, maxAttrValueLen),
						Attributes:    attrMap(sp.Attributes),
					},
					startNS: parseNanos(sp.StartTimeUnixNano),
					endNS:   parseNanos(sp.EndTimeUnixNano),
				}
				fs.Name = spanName(sp.Name, fs.Attributes)
				fs.DurationMS = round2(float64(fs.endNS-fs.startNS) / 1e6)
				all = append(all, fs)
			}
		}
	}
	if len(all) == 0 {
		out.Warning = "trace not found or has no spans"
		return out
	}

	byID := make(map[string]*flatSpan, len(all))
	var traceStart, traceEnd int64
	for i, fs := range all {
		byID[fs.SpanID] = fs
		if i == 0 || fs.startNS < traceStart {
			traceStart = fs.startNS
		}
		if fs.endNS > traceEnd {
			traceEnd = fs.endNS
		}
	}
	depths := make(map[string]int, len(all))
	var depthOf func(fs *flatSpan, guard int) int
	depthOf = func(fs *flatSpan, guard int) int {
		if d, ok := depths[fs.SpanID]; ok {
			return d
		}
		parent, ok := byID[fs.ParentID]
		if fs.ParentID == "" || !ok || guard > len(all) {
			depths[fs.SpanID] = 0
			return 0
		}
		d := depthOf(parent, guard+1) + 1
		depths[fs.SpanID] = d
		return d
	}

	children := map[string][]*flatSpan{}
	for _, fs := range all {
		if _, ok := byID[fs.ParentID]; ok && fs.ParentID != fs.SpanID {
			children[fs.ParentID] = append(children[fs.ParentID], fs)
		}
	}

	svcStats := map[string]*ServiceSummary{}
	for _, fs := range all {
		fs.Depth = depthOf(fs, 0)
		fs.SelfTimeMS = round2(float64(selfTimeNS(fs, children[fs.SpanID])) / 1e6)
		fs.OffsetMS = round2(float64(fs.startNS-traceStart) / 1e6)
		st := svcStats[fs.Service]
		if st == nil {
			st = &ServiceSummary{Name: fs.Service}
			svcStats[fs.Service] = st
		}
		st.Spans++
		st.SelfTimeMS = round2(st.SelfTimeMS + fs.SelfTimeMS)
		if fs.Error {
			st.Errors++
		}
	}

	out.Start = time.Unix(0, traceStart).UTC().Format(time.RFC3339Nano)
	out.DurationMS = round2(float64(traceEnd-traceStart) / 1e6)
	out.TotalSpans = len(all)
	for _, st := range svcStats {
		out.Services = append(out.Services, *st)
	}
	sort.Slice(out.Services, func(i, j int) bool { return out.Services[i].SelfTimeMS > out.Services[j].SelfTimeMS })

	sort.SliceStable(all, func(i, j int) bool { return all[i].startNS < all[j].startNS })
	var candidates []*flatSpan
	for _, fs := range all {
		if fs.Error && len(out.Errors) < maxErrorSpans {
			out.Errors = append(out.Errors, fs.Span)
		}
		if service != "" && fs.Service != service {
			continue
		}
		if minDurationMS > 0 && fs.DurationMS < minDurationMS && !fs.Error && fs.Depth != 0 {
			continue
		}
		candidates = append(candidates, fs)
	}

	for _, fs := range candidates {
		out.Spans = append(out.Spans, fs.Span)
	}
	matching := len(out.Spans)
	keepSpans(&out, maxSpans)
	fitTraceOutput(&out)
	if out.ShownSpans < matching {
		out.Warning = joinWarning(out.Warning, fmt.Sprintf("showing %d of %d matching spans (roots, errors, then slowest); use service/min_duration_ms to focus", out.ShownSpans, matching))
	}
	return out
}

func keepSpans(out *GetTraceOutput, n int) {
	if len(out.Spans) > n {
		sort.SliceStable(out.Spans, func(i, j int) bool {
			a, b := out.Spans[i], out.Spans[j]
			if (a.Depth == 0) != (b.Depth == 0) {
				return a.Depth == 0
			}
			if a.Error != b.Error {
				return a.Error
			}
			return a.DurationMS > b.DurationMS
		})
		out.Spans = out.Spans[:n]
	}
	sort.SliceStable(out.Spans, func(i, j int) bool { return out.Spans[i].OffsetMS < out.Spans[j].OffsetMS })
	out.ShownSpans = len(out.Spans)
}

func selfTimeNS(fs *flatSpan, kids []*flatSpan) int64 {
	total := fs.endNS - fs.startNS
	if total <= 0 {
		return 0
	}
	type iv struct{ s, e int64 }
	var ivs []iv
	for _, k := range kids {
		s, e := max(k.startNS, fs.startNS), min(k.endNS, fs.endNS)
		if e > s {
			ivs = append(ivs, iv{s, e})
		}
	}
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].s < ivs[j].s })
	var covered, curS, curE int64
	for i, v := range ivs {
		if i == 0 || v.s > curE {
			covered += curE - curS
			curS, curE = v.s, v.e
		} else if v.e > curE {
			curE = v.e
		}
	}
	covered += curE - curS
	return total - covered
}

func fitTraceOutput(out *GetTraceOutput) {
	if traceSize(out) <= traceOutputBudget {
		return
	}
	for i := range out.Spans {
		if !out.Spans[i].Error {
			out.Spans[i].Attributes = nil
		}
	}
	for i := range out.Errors {
		out.Errors[i].Attributes = nil
	}
	for traceSize(out) > traceOutputBudget && len(out.Spans) > 1 {
		keepSpans(out, len(out.Spans)*4/5)
	}
	out.Warning = joinWarning(out.Warning, "attributes dropped from non-error spans to fit the size budget")
}

func traceSize(out *GetTraceOutput) int {
	b, _ := json.Marshal(out)
	return len(b)
}

func (h *ToolHandlers) GetTraceTags(ctx context.Context, in GetTraceTagsInput) (GetTraceTagsOutput, error) {
	start := time.Now()
	out := GetTraceTagsOutput{Scopes: map[string][]string{}}
	st, et, _, err := h.resolveRange(in.StartTime, in.EndTime, time.Hour)
	if err != nil {
		return out, h.fail("get_trace_tags", start, err)
	}
	resp, err := h.client.Tags(ctx, TagsRequest{Scope: in.Scope, Start: st, End: et})
	if err != nil {
		return out, h.fail("get_trace_tags", start, fmt.Errorf("tempo tags failed: %w", err))
	}
	count := 0
	for _, sc := range resp.Scopes {
		tags := append([]string(nil), sc.Tags...)
		sort.Strings(tags)
		out.Scopes[sc.Name] = tags
		count += len(tags)
	}
	h.audit.ToolInvoked("get_trace_tags", time.Since(start).Milliseconds(), slog.Int("result_count", count))
	return out, nil
}

func (h *ToolHandlers) GetTraceTagValues(ctx context.Context, in GetTraceTagValuesInput) (GetTraceTagValuesOutput, error) {
	start := time.Now()
	out := GetTraceTagValuesOutput{Tag: in.Tag, Values: []string{}}
	if strings.TrimSpace(in.Tag) == "" {
		return out, h.fail("get_trace_tag_values", start, fmt.Errorf("tag is required, scoped like resource.service.name or span.http.route"))
	}
	st, et, _, err := h.resolveRange(in.StartTime, in.EndTime, time.Hour)
	if err != nil {
		return out, h.fail("get_trace_tag_values", start, err)
	}
	resp, err := h.client.TagValues(ctx, TagValuesRequest{Tag: in.Tag, Query: in.TraceQL, Start: st, End: et})
	if err != nil {
		return out, h.fail("get_trace_tag_values", start, fmt.Errorf("tempo tag values failed: %w", err))
	}
	for _, v := range resp.TagValues {
		out.Values = append(out.Values, v.Value)
	}
	sort.Strings(out.Values)
	out.Total = len(out.Values)
	if limit := clamp(in.Limit, defaultTagValuesLimit, maxTagValuesLimit); len(out.Values) > limit {
		out.Values = out.Values[:limit]
		out.Truncated = true
	}
	h.audit.ToolInvoked("get_trace_tag_values", time.Since(start).Milliseconds(), slog.String("tag", in.Tag), slog.Int("result_count", out.Total))
	return out, nil
}

func attrMap(attrs []Attribute) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		if isSensitiveKey(a.Key) {
			continue
		}
		m[a.Key] = truncate(a.Value.String(), maxAttrValueLen)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, frag := range sensitiveAttrFragments {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return false
}

func spanName(name string, attrs map[string]string) string {
	if name != "" {
		return name
	}
	if m, p := attrs["http.request.method"], attrs["url.path"]; m != "" || p != "" {
		return strings.TrimSpace(m + " " + p)
	}
	if r := attrs["rpc.method"]; r != "" {
		return r
	}
	return "(unnamed)"
}

func otlpID(id string) string {
	if id == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(id); err == nil {
		return hex.EncodeToString(b)
	}
	return id
}

func parseNanos(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func nanosToTime(s string) time.Time {
	return time.Unix(0, parseNanos(s))
}

func nanosStrToMS(s string) float64 {
	return round2(float64(parseNanos(s)) / 1e6)
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

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

func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

func joinWarning(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}
