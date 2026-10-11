package tempo

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

type fakeClient struct {
	search    *SearchResponse
	trace     *TraceResponse
	tagValues []string
	lastReq   SearchRequest
}

func (f *fakeClient) Search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	f.lastReq = req
	return f.search, nil
}
func (f *fakeClient) Trace(ctx context.Context, req TraceRequest) (*TraceResponse, error) {
	return f.trace, nil
}
func (f *fakeClient) Tags(ctx context.Context, req TagsRequest) (*TagsResponse, error) {
	return &TagsResponse{Scopes: []TagScope{{Name: "span", Tags: []string{"url.path", "http.route"}}}}, nil
}
func (f *fakeClient) TagValues(ctx context.Context, req TagValuesRequest) (*TagValuesResponse, error) {
	resp := &TagValuesResponse{}
	for _, v := range f.tagValues {
		resp.TagValues = append(resp.TagValues, TagValue{Type: "string", Value: v})
	}
	return resp, nil
}
func (f *fakeClient) Echo(ctx context.Context) error { return nil }

func newTestHandlers(fc *fakeClient) *ToolHandlers {
	return NewToolHandlers(fc, 24*time.Hour, audit.New(slog.New(slog.NewTextHandler(io.Discard, nil))))
}

func b64(hexID string) string {
	b, _ := hex.DecodeString(hexID)
	return base64.StdEncoding.EncodeToString(b)
}

func strAttr(k, v string) Attribute {
	return Attribute{Key: k, Value: AttributeValue{StringValue: &v}}
}

func span(id, parent, name string, startMS, durMS int64, attrs ...Attribute) OTLPSpan {
	base := int64(1_700_000_000_000_000_000)
	s := OTLPSpan{
		SpanID:            b64(id),
		Name:              name,
		Kind:              "SPAN_KIND_SERVER",
		StartTimeUnixNano: fmt.Sprint(base + startMS*1e6),
		EndTimeUnixNano:   fmt.Sprint(base + (startMS+durMS)*1e6),
		Attributes:        attrs,
	}
	if parent != "" {
		s.ParentSpanID = b64(parent)
	}
	return s
}

func resource(service string, spans ...OTLPSpan) ResourceSpans {
	var rs ResourceSpans
	rs.Resource.Attributes = []Attribute{strAttr("service.name", service)}
	rs.ScopeSpans = append(rs.ScopeSpans, struct {
		Spans []OTLPSpan `json:"spans"`
	}{Spans: spans})
	return rs
}

func sampleTrace() *TraceResponse {
	failing := span("0000000000000003", "0000000000000002", "walletpb.WalletService/GetWallet", 20, 8)
	failing.Kind = "SPAN_KIND_CLIENT"
	failing.Status.Code = "STATUS_CODE_ERROR"
	failing.Status.Message = "No wallet found"
	tr := &TraceResponse{}
	tr.Trace.ResourceSpans = []ResourceSpans{
		resource("user-gateway",
			span("0000000000000001", "", "", 0, 300, strAttr("http.request.method", "GET"), strAttr("url.path", "/v2/rewards/balances")),
			span("0000000000000002", "0000000000000001", "handler", 5, 250),
			failing,
		),
		resource("commerce-service",
			span("0000000000000004", "0000000000000002", "sql.query", 40, 200,
				strAttr("db.statement", "SELECT 1"),
				strAttr("db.connection_string", "postgres://user:hunter2@db:5432/x")),
			span("0000000000000005", "0000000000000002", "sql.conn.reset_session", 41, 0),
		),
	}
	return tr
}

func TestGetTrace_BuildsTree(t *testing.T) {
	h := newTestHandlers(&fakeClient{trace: sampleTrace()})
	out, err := h.GetTrace(context.Background(), GetTraceInput{TraceID: "abc"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.TotalSpans != 5 || out.ShownSpans != 5 {
		t.Fatalf("spans total=%d shown=%d", out.TotalSpans, out.ShownSpans)
	}
	if out.DurationMS != 300 {
		t.Fatalf("duration = %v", out.DurationMS)
	}
	root := out.Spans[0]
	if root.SpanID != "0000000000000001" || root.Depth != 0 || root.Name != "GET /v2/rewards/balances" {
		t.Fatalf("root = %+v", root)
	}
	if len(out.Errors) != 1 || out.Errors[0].StatusMessage != "No wallet found" || out.Errors[0].Kind != "client" || out.Errors[0].Depth != 2 {
		t.Fatalf("errors = %+v", out.Errors)
	}
	if out.Services[0].Name != "commerce-service" || out.Services[0].SelfTimeMS != 200 {
		t.Fatalf("services = %+v", out.Services)
	}
	var total float64
	for _, s := range out.Services {
		total += s.SelfTimeMS
	}
	if total != out.DurationMS {
		t.Fatalf("self times sum to %v, want trace duration %v", total, out.DurationMS)
	}
}

func TestSelfTime_MergesOverlappingChildren(t *testing.T) {
	mk := func(s, e int64) *flatSpan { return &flatSpan{startNS: s, endNS: e} }
	parent := mk(0, 100)
	kids := []*flatSpan{mk(10, 40), mk(30, 60), mk(90, 150)}
	if got := selfTimeNS(parent, kids); got != 40 {
		t.Fatalf("self = %d, want 40", got)
	}
}

func TestWithSpanNames(t *testing.T) {
	if got := withSpanNames("{status=error}"); got != "{status=error} | select(name)" {
		t.Fatalf("got %q", got)
	}
	if got := withSpanNames("{a=1} | select(span.x)"); got != "{a=1} | select(span.x)" {
		t.Fatalf("existing select should be kept, got %q", got)
	}
}

func TestGetTrace_DropsSensitiveAttributes(t *testing.T) {
	h := newTestHandlers(&fakeClient{trace: sampleTrace()})
	out, _ := h.GetTrace(context.Background(), GetTraceInput{TraceID: "abc"})
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "connection_string") {
		t.Fatalf("sensitive attribute leaked: %s", b)
	}
	if !strings.Contains(string(b), "SELECT 1") {
		t.Fatal("expected db.statement to be kept")
	}
}

func TestGetTrace_FiltersByServiceAndDuration(t *testing.T) {
	h := newTestHandlers(&fakeClient{trace: sampleTrace()})
	out, _ := h.GetTrace(context.Background(), GetTraceInput{TraceID: "abc", Service: "commerce-service", MinDurationMS: 1})
	if len(out.Spans) != 1 || out.Spans[0].Name != "sql.query" {
		t.Fatalf("spans = %+v", out.Spans)
	}
	if len(out.Errors) != 1 {
		t.Fatalf("errors should cover the whole trace, got %d", len(out.Errors))
	}
}

func TestGetTrace_CapsSpansKeepingRootAndErrors(t *testing.T) {
	h := newTestHandlers(&fakeClient{trace: sampleTrace()})
	out, _ := h.GetTrace(context.Background(), GetTraceInput{TraceID: "abc", MaxSpans: 3})
	if out.ShownSpans != 3 || out.Warning == "" {
		t.Fatalf("shown=%d warning=%q", out.ShownSpans, out.Warning)
	}
	names := map[string]bool{}
	for _, s := range out.Spans {
		names[s.SpanID] = true
	}
	if !names["0000000000000001"] || !names["0000000000000003"] || !names["0000000000000002"] {
		t.Fatalf("expected root, error and slowest span, got %+v", out.Spans)
	}
}

func TestGetTrace_FitsSizeBudget(t *testing.T) {
	tr := &TraceResponse{}
	var spans []OTLPSpan
	spans = append(spans, span("0000000000000001", "", "root", 0, 10_000))
	long := strings.Repeat("x", 290)
	for i := 2; i < 300; i++ {
		spans = append(spans, span(fmt.Sprintf("%016x", i), "0000000000000001", "child", int64(i), 5, strAttr("db.statement", long), strAttr("a", long)))
	}
	spans[len(spans)-1].Status.Code = "STATUS_CODE_ERROR"
	tr.Trace.ResourceSpans = []ResourceSpans{resource("svc", spans...)}
	h := newTestHandlers(&fakeClient{trace: tr})
	out, _ := h.GetTrace(context.Background(), GetTraceInput{TraceID: "abc", MaxSpans: 300})
	if traceSize(&out) > traceOutputBudget {
		t.Fatalf("output %d bytes exceeds budget", traceSize(&out))
	}
	if out.Spans[0].Name != "root" || !strings.Contains(out.Warning, "size budget") {
		t.Fatalf("first=%q warning=%q", out.Spans[0].Name, out.Warning)
	}
	var sawErr bool
	for _, s := range out.Spans {
		sawErr = sawErr || s.Error
	}
	if !sawErr {
		t.Fatal("late error span was cut while shrinking")
	}
}

func TestSearchTraces_SummarizesAndBounds(t *testing.T) {
	dur := "1500000"
	fc := &fakeClient{search: &SearchResponse{Traces: []SearchTrace{{
		TraceID: "abc", RootServiceName: "wallet-service", DurationMs: 1200, StartTimeUnixNano: "1700000000000000000",
		ServiceStats: map[string]ServiceStats{"wallet-service": {SpanCount: 4, ErrorCount: 1}},
		SpanSets:     []SpanSet{{Spans: []SearchSpan{{SpanID: "s1", DurationNanos: dur, Attributes: []Attribute{strAttr("service.name", "wallet-service"), strAttr("http.route", "/x")}}}}},
	}}}}
	h := newTestHandlers(fc)
	out, err := h.SearchTraces(context.Background(), SearchTracesInput{TraceQL: "{status=error}", Limit: 500})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fc.lastReq.Query != "{status=error} | select(name)" || out.Query != "{status=error}" {
		t.Fatalf("sent %q, reported %q", fc.lastReq.Query, out.Query)
	}
	if fc.lastReq.Limit != maxSearchLimit {
		t.Fatalf("limit = %d, want clamp to %d", fc.lastReq.Limit, maxSearchLimit)
	}
	tr := out.Traces[0]
	if tr.MatchedSpans[0].DurationMS != 1.5 || tr.MatchedSpans[0].Attributes["http.route"] != "/x" {
		t.Fatalf("matched = %+v", tr.MatchedSpans)
	}
	if _, ok := tr.MatchedSpans[0].Attributes["service.name"]; ok {
		t.Fatal("service.name should be dropped from matched span attributes")
	}
}

func TestSearchTraces_RequiresQuery(t *testing.T) {
	h := newTestHandlers(&fakeClient{})
	if _, err := h.SearchTraces(context.Background(), SearchTracesInput{}); err == nil {
		t.Fatal("expected error for empty traceql")
	}
}

func TestGetTraceTagValues_Truncates(t *testing.T) {
	var vals []string
	for i := 0; i < 150; i++ {
		vals = append(vals, fmt.Sprintf("v%03d", i))
	}
	h := newTestHandlers(&fakeClient{tagValues: vals})
	out, err := h.GetTraceTagValues(context.Background(), GetTraceTagValuesInput{Tag: "span.http.route"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Values) != defaultTagValuesLimit || out.Total != 150 || !out.Truncated {
		t.Fatalf("values=%d total=%d truncated=%v", len(out.Values), out.Total, out.Truncated)
	}
}
