package cloudflare

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

type fakeClient struct {
	data      string
	lastQuery string
	calls     int
}

func (f *fakeClient) Query(ctx context.Context, query string) (*Response, error) {
	f.calls++
	f.lastQuery = query
	return &Response{Data: json.RawMessage(f.data)}, nil
}

const tagEng = "e58607c2de82ee0a6495d4a4c92d981b"

func newTestHandlers(fc *fakeClient) *ToolHandlers {
	zones := map[string]string{"grey.engineering": tagEng, "grey.co": "ce068f01875cb464a6aface167b0510b"}
	return NewToolHandlers(fc, zones, 24*time.Hour, audit.New(slog.New(slog.NewTextHandler(io.Discard, nil))))
}

func validInput() QueryCloudflareInput {
	return QueryCloudflareInput{
		Zone:      "grey.engineering",
		Dataset:   "httpRequestsAdaptiveGroups",
		StartTime: "2025-01-01T00:00:00Z",
		EndTime:   "2025-01-01T01:00:00Z",
		Fields:    "count dimensions { edgeResponseStatus }",
	}
}

func TestQuery_BuildsQueryAndReturnsRows(t *testing.T) {
	fc := &fakeClient{data: `{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[{"count":7,"dimensions":{"edgeResponseStatus":502}}]}]}}`}
	h := newTestHandlers(fc)
	in := validInput()
	in.Filter = map[string]any{"clientRequestHTTPHost": "app.grey.co", "edgeResponseStatus_geq": float64(500)}
	in.Limit = 10
	out, err := h.QueryCloudflare(context.Background(), in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := `{ viewer { zones(filter: {zoneTag: "` + tagEng + `"}) { httpRequestsAdaptiveGroups(limit: 10, filter: {clientRequestHTTPHost: "app.grey.co", datetime_geq: "2025-01-01T00:00:00Z", datetime_leq: "2025-01-01T01:00:00Z", edgeResponseStatus_geq: 500}, orderBy: [count_DESC]) { count dimensions { edgeResponseStatus } } } } }`
	if fc.lastQuery != want {
		t.Fatalf("query =\n%s\nwant\n%s", fc.lastQuery, want)
	}
	if out.Query != want || out.RowCount != 1 || out.Zone != "grey.engineering" || out.Dataset != "httpRequestsAdaptiveGroups" {
		t.Fatalf("out = %+v", out)
	}
	if out.Rows[0]["count"].(float64) != 7 || !strings.Contains(out.Note, "sampled") {
		t.Fatalf("rows/note = %+v / %q", out.Rows, out.Note)
	}
}

func TestQuery_DefaultOrderByAndLimit(t *testing.T) {
	cases := map[string]string{
		"httpRequestsAdaptive":       "orderBy: [datetime_DESC]",
		"httpRequestsAdaptiveGroups": "orderBy: [count_DESC]",
		"firewallEventsAdaptive":     "orderBy: [datetime_DESC]",
	}
	for ds, want := range cases {
		fc := &fakeClient{data: `{"viewer":{"zones":[{"` + ds + `":[]}]}}`}
		in := validInput()
		in.Dataset = ds
		if _, err := newTestHandlers(fc).QueryCloudflare(context.Background(), in); err != nil {
			t.Fatalf("%s: %v", ds, err)
		}
		if !strings.Contains(fc.lastQuery, want) || !strings.Contains(fc.lastQuery, "limit: 100,") {
			t.Fatalf("%s: query = %s", ds, fc.lastQuery)
		}
	}
}

func TestQuery_CustomOrderBy(t *testing.T) {
	fc := &fakeClient{data: `{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[]}]}}`}
	in := validInput()
	in.OrderBy = []string{"count_DESC", "sum_edgeResponseBytes_ASC"}
	if _, err := newTestHandlers(fc).QueryCloudflare(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fc.lastQuery, "orderBy: [count_DESC, sum_edgeResponseBytes_ASC]") {
		t.Fatalf("query = %s", fc.lastQuery)
	}
}

func TestBuildFilterLiteral(t *testing.T) {
	st := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	et := st.Add(time.Hour)
	filter := map[string]any{
		"clientRequestPath": `/a"b\c`,
		"ok":                true,
		"ratio":             1.5,
		"statuses":          []any{float64(500), float64(502)},
		"OR": []any{
			map[string]any{"a": "x"},
			map[string]any{"AND": []any{map[string]any{"b": float64(1)}, map[string]any{"c": "y"}}},
		},
		"nested": map[string]any{"k": "v"},
	}
	got, err := buildFilterLiteral(filter, st, et)
	if err != nil {
		t.Fatal(err)
	}
	want := `{OR: [{a: "x"}, {AND: [{b: 1}, {c: "y"}]}], clientRequestPath: "/a\"b\\c", datetime_geq: "2025-01-01T00:00:00Z", datetime_leq: "2025-01-01T01:00:00Z", nested: {k: "v"}, ok: true, ratio: 1.5, statuses: [500, 502]}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestBuildFilterLiteral_OnlyDatetime(t *testing.T) {
	st := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := buildFilterLiteral(nil, st, st.Add(time.Minute))
	if err != nil || got != `{datetime_geq: "2025-01-01T00:00:00Z", datetime_leq: "2025-01-01T00:01:00Z"}` {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestQuery_Rejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*QueryCloudflareInput)
		want   string
	}{
		{"fields bad chars", func(in *QueryCloudflareInput) { in.Fields = "count } } { evil(a: 1)" }, "only contain"},
		{"fields quote", func(in *QueryCloudflareInput) { in.Fields = `count "x"` }, "only contain"},
		{"fields extra close", func(in *QueryCloudflareInput) { in.Fields = "count }" }, "unbalanced"},
		{"fields unclosed", func(in *QueryCloudflareInput) { in.Fields = "dimensions { a" }, "unbalanced"},
		{"fields close before open", func(in *QueryCloudflareInput) { in.Fields = "} a {" }, "unbalanced"},
		{"fields empty", func(in *QueryCloudflareInput) { in.Fields = "  " }, "fields is required"},
		{"bad filter key", func(in *QueryCloudflareInput) { in.Filter = map[string]any{"a b": "x"} }, "invalid filter key"},
		{"bad nested filter key", func(in *QueryCloudflareInput) {
			in.Filter = map[string]any{"AND": []any{map[string]any{"x}": 1.0}}}
		}, "invalid filter key"},
		{"user datetime_geq", func(in *QueryCloudflareInput) { in.Filter = map[string]any{"datetime_geq": "2020-01-01T00:00:00Z"} }, "datetime_geq"},
		{"user datetime_leq", func(in *QueryCloudflareInput) { in.Filter = map[string]any{"datetime_leq": "2020-01-01T00:00:00Z"} }, "datetime_leq"},
		{"filter null", func(in *QueryCloudflareInput) { in.Filter = map[string]any{"a": nil} }, "unsupported value"},
		{"filter nested array", func(in *QueryCloudflareInput) { in.Filter = map[string]any{"a": []any{[]any{1.0}}} }, "nested arrays"},
		{"bad order_by", func(in *QueryCloudflareInput) { in.OrderBy = []string{"count"} }, "invalid order_by"},
		{"order_by injection", func(in *QueryCloudflareInput) { in.OrderBy = []string{"count_DESC]) { x"} }, "invalid order_by"},
		{"unknown zone", func(in *QueryCloudflareInput) { in.Zone = "nope.com" }, "grey.co, grey.engineering"},
		{"unknown dataset", func(in *QueryCloudflareInput) { in.Dataset = "workersInvocations" }, "unknown dataset"},
		{"span too long", func(in *QueryCloudflareInput) {
			in.StartTime = "2025-01-01T00:00:00Z"
			in.EndTime = "2025-01-03T00:00:00Z"
		}, "exceeds the maximum"},
		{"limit over cap", func(in *QueryCloudflareInput) { in.Limit = 1001 }, "limit must be"},
		{"limit negative", func(in *QueryCloudflareInput) { in.Limit = -1 }, "limit must be"},
		{"bad start", func(in *QueryCloudflareInput) { in.StartTime = "garbage" }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeClient{data: `{}`}
			in := validInput()
			tc.mutate(&in)
			_, err := newTestHandlers(fc).QueryCloudflare(context.Background(), in)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if fc.calls != 0 {
				t.Fatal("client must not be called on a rejected request")
			}
		})
	}
}

func TestQuery_LimitAtCapAccepted(t *testing.T) {
	fc := &fakeClient{data: `{"viewer":{"zones":[{"httpRequestsAdaptiveGroups":[]}]}}`}
	in := validInput()
	in.Limit = 1000
	if _, err := newTestHandlers(fc).QueryCloudflare(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fc.lastQuery, "limit: 1000,") {
		t.Fatalf("query = %s", fc.lastQuery)
	}
}

func TestQuery_NoZoneInResponse(t *testing.T) {
	fc := &fakeClient{data: `{"viewer":{"zones":[]}}`}
	if _, err := newTestHandlers(fc).QueryCloudflare(context.Background(), validInput()); err == nil {
		t.Fatal("expected error when no zone is returned")
	}
}

func TestSource_HealthCheck(t *testing.T) {
	fc := &fakeClient{data: `{"viewer":{"zones":[{"zoneTag":"` + tagEng + `"}]}}`}
	src := &Source{handlers: newTestHandlers(fc)}
	err := src.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "grey.co") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(fc.lastQuery, "zoneTag_in: [") || !strings.Contains(fc.lastQuery, tagEng) {
		t.Fatalf("query = %s", fc.lastQuery)
	}
	fc.data = `{"viewer":{"zones":[{"zoneTag":"` + tagEng + `"},{"zoneTag":"ce068f01875cb464a6aface167b0510b"}]}}`
	if err := src.HealthCheck(context.Background()); err != nil {
		t.Fatalf("err = %v", err)
	}
}
