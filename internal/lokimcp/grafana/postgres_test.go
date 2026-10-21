package grafana

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

func newPostgresHandlers(fc *fakeClient) *ToolHandlers {
	return NewToolHandlers(fc, HandlerConfig{PostgresDatasources: map[string]string{
		"grey-aurora-db-transaction-prod-reader-1": "pg-reader",
		"grey-db-audit-prod":                       "pg-audit",
	}}, audit.New(slog.New(slog.NewTextHandler(io.Discard, nil))))
}

func TestExplainQuerySendsOnlyTheExplainCall(t *testing.T) {
	fc := &fakeClient{resp: frameResp(
		`{"fields":[{"name":"explain_plan","type":"string"}]}`,
		`[["Limit  (cost=0.56..8.60 rows=2 width=24)","  ->  Index Scan Backward using idx on transactions t"]]`,
	)}
	h := newPostgresHandlers(fc)
	out, err := h.ExplainQuery(context.Background(), ExplainInput{
		Database: "grey-aurora-db-transaction-prod-reader-1",
		Query:    "SELECT t.id FROM transactions t WHERE t.owner_id = $1 ORDER BY t.created_at DESC LIMIT 2;",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := fc.lastQuery["datasource"].(map[string]string)["uid"]; got != "pg-reader" {
		t.Fatalf("datasource uid = %q", got)
	}
	want := "SELECT * FROM diag.explain_plan($lk$SELECT t.id FROM transactions t WHERE t.owner_id = $1 ORDER BY t.created_at DESC LIMIT 2$lk$)"
	if got := fc.lastQuery["rawSql"]; got != want {
		t.Fatalf("rawSql =\n%v\nwant\n%v", got, want)
	}
	if len(out.Plan) != 2 || !strings.HasPrefix(out.Plan[0], "Limit") {
		t.Fatalf("plan = %#v", out.Plan)
	}
	if out.Datasource != "pg-reader" {
		t.Fatalf("datasource = %q", out.Datasource)
	}
}

func TestExplainQueryRejectsBeforeSending(t *testing.T) {
	cases := []struct{ name, db, query, errHas string }{
		{"unknown database", "nope", "SELECT 1", "unknown database"},
		{"empty query", "grey-db-audit-prod", "  ", "query is required"},
		{"delete", "grey-db-audit-prod", "DELETE FROM audit_logs", "only SELECT, WITH or VALUES"},
		{"stacked statement", "grey-db-audit-prod", "SELECT 1; DELETE FROM audit_logs", "single statement"},
		{"comment hides delete", "grey-db-audit-prod", "/* SELECT */ DELETE FROM audit_logs", "only SELECT, WITH or VALUES"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fc := &fakeClient{}
			_, err := newPostgresHandlers(fc).ExplainQuery(context.Background(), ExplainInput{Database: c.db, Query: c.query})
			if err == nil || !strings.Contains(err.Error(), c.errHas) {
				t.Fatalf("err = %v, want containing %q", err, c.errHas)
			}
			if fc.lastQuery != nil {
				t.Fatalf("query was sent to grafana: %v", fc.lastQuery)
			}
		})
	}
}

func TestExplainQueryAllowsSemicolonInsideLiteral(t *testing.T) {
	fc := &fakeClient{resp: frameResp(`{"fields":[{"name":"explain_plan","type":"string"}]}`, `[["Seq Scan on t"]]`)}
	if _, err := newPostgresHandlers(fc).ExplainQuery(context.Background(), ExplainInput{
		Database: "grey-db-audit-prod",
		Query:    "SELECT * FROM audit_logs WHERE http_path = 'a;b'",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExplainQueryPostgres14PlaceholderHint(t *testing.T) {
	fc := &fakeClient{resp: &QueryResponse{Results: map[string]QueryResult{"A": {Error: "pq: there is no parameter $1"}}}}
	_, err := newPostgresHandlers(fc).ExplainQuery(context.Background(), ExplainInput{
		Database: "grey-db-audit-prod",
		Query:    "SELECT * FROM audit_logs WHERE id = $1",
	})
	if err == nil || !strings.Contains(err.Error(), "PostgreSQL 14") {
		t.Fatalf("err = %v", err)
	}
}

func TestDollarQuoteAvoidsCollision(t *testing.T) {
	got := dollarQuote("SELECT '$lk$'")
	if got != "$lkx$SELECT '$lk$'$lkx$" {
		t.Fatalf("got %s", got)
	}
}
