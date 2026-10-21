package grafana

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	explainFunction = "diag.explain_plan"
	maxPlanLines    = 400
)

var sqlExplainLeading = regexp.MustCompile(`(?i)^\s*(select|with|values)\b`)

type ExplainInput struct {
	Database string
	Query    string
}

type ExplainOutput struct {
	Database   string   `json:"database"`
	Datasource string   `json:"datasource_uid"`
	Plan       []string `json:"plan"`
	Truncated  bool     `json:"truncated,omitempty"`
	Warning    string   `json:"warning,omitempty"`
}

func (h *ToolHandlers) PostgresDatabases() []string {
	return h.postgresNames
}

func (h *ToolHandlers) ExplainQuery(ctx context.Context, in ExplainInput) (ExplainOutput, error) {
	start := time.Now()
	out := ExplainOutput{Database: in.Database, Plan: []string{}}
	uid, ok := h.postgresUIDs[in.Database]
	if !ok {
		return out, h.fail("explain_query", start, fmt.Errorf("unknown database %q; available: %s", in.Database, strings.Join(h.postgresNames, ", ")))
	}
	query, err := prepareExplainQuery(in.Query)
	if err != nil {
		return out, h.fail("explain_query", start, err)
	}
	out.Datasource = uid
	now := time.Now()
	resp, err := h.client.Query(ctx, QueryRequest{From: now.Add(-time.Hour), To: now, Queries: []map[string]any{{
		"refId":      "A",
		"datasource": map[string]string{"uid": uid},
		"format":     "table",
		"rawSql":     fmt.Sprintf("SELECT * FROM %s(%s)", explainFunction, dollarQuote(query)),
	}}})
	if err != nil {
		return out, h.fail("explain_query", start, fmt.Errorf("explain failed: %w", err))
	}
	res, err := resp.Single("A")
	if err != nil {
		if strings.Contains(err.Error(), "there is no parameter $") {
			err = fmt.Errorf("%w (this database runs PostgreSQL 14, which has no GENERIC_PLAN; replace $1-style placeholders with literal values)", err)
		}
		return out, h.fail("explain_query", start, fmt.Errorf("explain failed: %w", err))
	}
	for _, frame := range res.Frames {
		for r := 0; r < frame.RowCount(); r++ {
			out.Plan = append(out.Plan, fmt.Sprint(frame.Cell(0, r)))
		}
	}
	if len(out.Plan) > maxPlanLines {
		out.Plan = out.Plan[:maxPlanLines]
		out.Truncated = true
		out.Warning = fmt.Sprintf("plan cut to the first %d lines", maxPlanLines)
	}
	for jsonSize(out) > outputBudget && len(out.Plan) > 1 {
		out.Plan = out.Plan[:len(out.Plan)*4/5]
		out.Truncated = true
		out.Warning = fmt.Sprintf("plan cut to the first %d lines to fit the size budget", len(out.Plan))
	}
	h.audit.ToolInvoked("explain_query", time.Since(start).Milliseconds(), slog.String("database", in.Database), slog.String("query", query), slog.Int("result_count", len(out.Plan)))
	return out, nil
}

func prepareExplainQuery(raw string) (string, error) {
	query := strings.TrimSpace(raw)
	query = strings.TrimSpace(strings.TrimSuffix(query, ";"))
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	scrubbed := sqlStringLiteral.ReplaceAllString(sqlBlockComment.ReplaceAllString(sqlLineComment.ReplaceAllString(query, " "), " "), "''")
	if strings.Contains(scrubbed, ";") {
		return "", fmt.Errorf("only a single statement can be explained")
	}
	if !sqlExplainLeading.MatchString(scrubbed) {
		return "", fmt.Errorf("only SELECT, WITH or VALUES statements can be explained")
	}
	return query, nil
}

func dollarQuote(s string) string {
	tag := "lk"
	for strings.Contains(s, "$"+tag+"$") {
		tag += "x"
	}
	return "$" + tag + "$" + s + "$" + tag + "$"
}

func sortedNames(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
