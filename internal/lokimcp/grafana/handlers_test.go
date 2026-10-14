package grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

type fakeClient struct {
	resp      *QueryResponse
	resources map[string]string
	lastQuery map[string]any
	lastFrom  time.Time
}

func (f *fakeClient) Query(ctx context.Context, req QueryRequest) (*QueryResponse, error) {
	f.lastQuery = req.Queries[0]
	f.lastFrom = req.From
	return f.resp, nil
}

func (f *fakeClient) Resource(ctx context.Context, uid, path string, params url.Values, out any) error {
	return jsonInto(f.resources[path], out)
}

func (f *fakeClient) DataSource(ctx context.Context, uid string) (*DataSource, error) {
	return &DataSource{UID: uid, JSONData: map[string]any{"database": "loadbalancer"}}, nil
}

func jsonInto(s string, out any) error {
	return jsonUnmarshal([]byte(s), out)
}

func newTestHandlers(fc *fakeClient) *ToolHandlers {
	return NewToolHandlers(fc, HandlerConfig{AthenaUID: "ath", CloudWatchUID: "cw", CloudWatchMaxPoints: 100}, audit.New(slog.New(slog.NewTextHandler(io.Discard, nil))))
}

func frameResp(schema, values string) *QueryResponse {
	var r QueryResponse
	jsonUnmarshal([]byte(fmt.Sprintf(`{"results":{"A":{"status":200,"frames":[{"schema":%s,"data":{"values":%s}}]}}}`, schema, values)), &r)
	return &r
}

func TestPrepareAthenaSQL(t *testing.T) {
	st := time.Date(2026, 10, 13, 22, 0, 0, 0, time.UTC)
	et := time.Date(2026, 10, 14, 2, 0, 0, 0, time.UTC)
	cases := []struct {
		name, in, want, errHas string
	}{
		{"expands macro and adds limit", "SELECT count(*) FROM t WHERE $__dayFilter", "SELECT count(*) FROM t WHERE day BETWEEN '2026/10/13' AND '2026/10/14' LIMIT 100", ""},
		{"keeps smaller limit", "select * from t where day = '2026/10/14' limit 5;", "select * from t where day = '2026/10/14' limit 5", ""},
		{"lowers larger limit", "SELECT * FROM t WHERE $__dayFilter LIMIT 9999", "SELECT * FROM t WHERE day BETWEEN '2026/10/13' AND '2026/10/14' LIMIT 100", ""},
		{"with clause", "WITH x AS (SELECT * FROM t WHERE $__dayFilter) SELECT * FROM x", "WITH x AS (SELECT * FROM t WHERE day BETWEEN '2026/10/13' AND '2026/10/14') SELECT * FROM x LIMIT 100", ""},
		{"keyword inside string ok", "SELECT * FROM t WHERE $__dayFilter AND request_url LIKE '%delete%'", "", ""},
		{"requires day filter", "SELECT * FROM t", "", "day partition"},
		{"day only in string", "SELECT * FROM t WHERE x = 'day = 1'", "", "day partition"},
		{"rejects ddl", "DROP TABLE t", "", "SELECT or WITH"},
		{"rejects hidden ddl", "SELECT 1 FROM t WHERE $__dayFilter UNION SELECT * FROM t; DROP TABLE t", "", "single statement"},
		{"rejects insert keyword", "WITH a AS (SELECT 1) INSERT INTO t SELECT * FROM a WHERE day = '1'", "", "INSERT"},
		{"comment hides nothing", "SELECT * FROM t WHERE $__dayFilter -- ; drop", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := prepareAthenaSQL(c.in, st, et, 100)
			if c.errHas != "" {
				if err == nil || !strings.Contains(err.Error(), c.errHas) {
					t.Fatalf("err = %v, want containing %q", err, c.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if c.want != "" && got != c.want {
				t.Fatalf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestQueryAccessLogs_RowsAndBudget(t *testing.T) {
	long := strings.Repeat("u", 1000)
	vals := fmt.Sprintf(`[[%s],[%s]]`, strings.TrimSuffix(strings.Repeat(`503,`, 300), ","), strings.TrimSuffix(strings.Repeat(fmt.Sprintf(`"%s",`, long), 300), ","))
	fc := &fakeClient{resp: frameResp(`{"fields":[{"name":"elb_status_code","type":"number"},{"name":"request_url","type":"string"}]}`, vals)}
	h := newTestHandlers(fc)
	out, err := h.QueryAccessLogs(context.Background(), AthenaQueryInput{SQL: "SELECT elb_status_code, request_url FROM t WHERE $__dayFilter", MaxRows: 500})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fc.lastQuery["rawSQL"] != out.Query || fc.lastQuery["format"] != 1 {
		t.Fatalf("sent %v", fc.lastQuery)
	}
	if out.RowCount != 300 || !out.Truncated || jsonSize(out) > outputBudget {
		t.Fatalf("rows=%d shown=%d truncated=%v size=%d", out.RowCount, len(out.Rows), out.Truncated, jsonSize(out))
	}
	if s := out.Rows[0][1].(string); len(s) > maxCellLen+4 {
		t.Fatalf("cell not truncated: %d", len(s))
	}
}

func TestQueryAccessLogs_CapsRange(t *testing.T) {
	fc := &fakeClient{resp: frameResp(`{"fields":[]}`, `[]`)}
	h := newTestHandlers(fc)
	out, err := h.QueryAccessLogs(context.Background(), AthenaQueryInput{SQL: "SELECT 1 FROM t WHERE $__dayFilter", StartTime: "30d ago"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(out.Warning, "capped") || time.Since(fc.lastFrom) > 7*24*time.Hour+time.Minute {
		t.Fatalf("warning=%q from=%v", out.Warning, fc.lastFrom)
	}
}

func TestDescribeAccessLogs(t *testing.T) {
	fc := &fakeClient{resp: frameResp(`{"fields":[{"name":"table_name","type":"string"},{"name":"column_name","type":"string"},{"name":"data_type","type":"string"}]}`, `[["t","t"],["time","elb_status_code"],["varchar","integer"]]`)}
	h := newTestHandlers(fc)
	out, err := h.DescribeAccessLogs(context.Background(), DescribeInput{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Database != "loadbalancer" || len(out.Tables["t"]) != 2 || out.Tables["t"][1] != "elb_status_code integer" {
		t.Fatalf("out = %+v", out)
	}
	if !strings.Contains(fc.lastQuery["rawSQL"].(string), "table_schema = 'loadbalancer'") {
		t.Fatalf("sql = %v", fc.lastQuery["rawSQL"])
	}
}

func TestQueryCloudWatch_Series(t *testing.T) {
	fc := &fakeClient{resp: frameResp(`{"name":"db1","fields":[{"name":"Time","type":"time"},{"name":"Value","type":"number","labels":{"DBInstanceIdentifier":"db1","Series":"db1"}}]}`, `[[1700000000000,1700000060000],[0.1,null]]`)}
	h := newTestHandlers(fc)
	out, err := h.QueryCloudWatch(context.Background(), CloudWatchQueryInput{Namespace: "AWS/RDS", Metric: "CommitLatency", Dimensions: map[string]string{"DBInstanceIdentifier": "db1"}, Statistic: "max", StartTime: "1h ago"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	q := fc.lastQuery
	if q["statistic"] != "Maximum" || q["region"] != "default" || q["period"] != "60" || q["matchExact"] != true {
		t.Fatalf("query = %v", q)
	}
	if len(out.Series) != 1 || out.Series[0].Labels["DBInstanceIdentifier"] != "db1" || len(out.Series[0].Values) != 1 {
		t.Fatalf("series = %+v", out.Series)
	}
	if _, ok := out.Series[0].Labels["Series"]; ok {
		t.Fatal("Series label should be dropped")
	}
}

func TestQueryCloudWatch_RejectsBadStatistic(t *testing.T) {
	h := newTestHandlers(&fakeClient{})
	if _, err := h.QueryCloudWatch(context.Background(), CloudWatchQueryInput{Namespace: "AWS/RDS", Metric: "x", Statistic: "median"}); err == nil {
		t.Fatal("expected error")
	}
	if s, err := normalizeStatistic("P99"); err != nil || s != "p99" {
		t.Fatalf("p99 -> %q %v", s, err)
	}
}

func TestResolvePeriod(t *testing.T) {
	st := time.Unix(0, 0)
	if p := resolvePeriod(st, st.Add(time.Hour), 0, 100); p != 60 {
		t.Fatalf("1h -> %d", p)
	}
	if p := resolvePeriod(st, st.Add(7*24*time.Hour), 60, 1440); p != 420 {
		t.Fatalf("7d -> %d, want 420", p)
	}
	if p := resolvePeriod(st, st.Add(24*time.Hour+500*time.Millisecond), 0, 1440); p != 60 {
		t.Fatalf("24h+jitter -> %d, want 60", p)
	}
	if p := resolvePeriod(st, st.Add(time.Hour), 90, 1000); p != 120 {
		t.Fatalf("90 -> %d, want rounded to 120", p)
	}
}

func TestDimensions_ValuesTruncate(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 150; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"value":"q%03d"}`, i)
	}
	b.WriteString("]")
	h := newTestHandlers(&fakeClient{resources: map[string]string{"dimension-values": b.String()}})
	out, err := h.GetCloudWatchDimensions(context.Background(), DimensionsInput{Namespace: "AWS/SQS", Metric: "m", Key: "QueueName"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Values) != defaultDimensionValues || out.Total != 150 || !out.Truncated {
		t.Fatalf("values=%d total=%d", len(out.Values), out.Total)
	}
}

func jsonUnmarshal(b []byte, out any) error { return json.Unmarshal(b, out) }
