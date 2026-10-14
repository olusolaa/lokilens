package grafana

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAthenaRows = 100
	maxAthenaRows     = 500
	maxCellLen        = 300
	dayFilterMacro    = "$__dayFilter"
)

var (
	sqlStringLiteral = regexp.MustCompile(`'(?:[^']|'')*'`)
	sqlLineComment   = regexp.MustCompile(`--[^\n]*`)
	sqlBlockComment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	sqlForbidden     = regexp.MustCompile(`(?i)\b(insert|update|delete|drop|create|alter|msck|unload|grant|revoke|merge|call|prepare|execute|deallocate|vacuum|optimize)\b`)
	sqlLeading       = regexp.MustCompile(`(?i)^\s*(select|with)\b`)
	sqlDayPredicate  = regexp.MustCompile(`(?i)\bday\b\s*(=|>=|<=|>|<|between\b|in\b)`)
	sqlTrailingLimit = regexp.MustCompile(`(?i)\blimit\s+(\d+)\s*$`)
)

type AthenaQueryInput struct {
	SQL       string
	StartTime string
	EndTime   string
	MaxRows   int
}

type AthenaQueryOutput struct {
	Query     string   `json:"query_executed"`
	TimeRange string   `json:"time_range"`
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	RowCount  int      `json:"row_count"`
	Truncated bool     `json:"truncated,omitempty"`
	Warning   string   `json:"warning,omitempty"`
}

type DescribeInput struct {
	Table string
}

type DescribeOutput struct {
	Database string              `json:"database"`
	Tables   map[string][]string `json:"tables"`
	Note     string              `json:"note"`
}

func (h *ToolHandlers) DescribeAccessLogs(ctx context.Context, in DescribeInput) (DescribeOutput, error) {
	start := time.Now()
	out := DescribeOutput{Tables: map[string][]string{}}
	db, err := h.athenaDatabase(ctx)
	if err != nil {
		return out, h.fail("describe_access_logs", start, err)
	}
	out.Database = db
	sql := fmt.Sprintf("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = '%s'", escapeSQL(db))
	if in.Table != "" {
		sql += fmt.Sprintf(" AND table_name = '%s'", escapeSQL(in.Table))
	}
	sql += " ORDER BY table_name, ordinal_position"
	now := time.Now()
	frame, err := h.athenaFrame(ctx, sql, now.Add(-time.Hour), now)
	if err != nil {
		return out, h.fail("describe_access_logs", start, err)
	}
	for r := 0; r < frame.RowCount(); r++ {
		table := fmt.Sprint(frame.Cell(0, r))
		out.Tables[table] = append(out.Tables[table], fmt.Sprintf("%v %v", frame.Cell(1, r), frame.Cell(2, r)))
	}
	out.Note = "Tables are partitioned by day ('yyyy/MM/dd'). Every query must filter on day; use $__dayFilter to cover the requested window."
	h.audit.ToolInvoked("describe_access_logs", time.Since(start).Milliseconds(), slog.Int("result_count", len(out.Tables)))
	return out, nil
}

func (h *ToolHandlers) QueryAccessLogs(ctx context.Context, in AthenaQueryInput) (AthenaQueryOutput, error) {
	start := time.Now()
	out := AthenaQueryOutput{Columns: []string{}, Rows: [][]any{}}
	st, et, warn, err := resolveRange(in.StartTime, in.EndTime, time.Hour, h.athenaMaxRange)
	if err != nil {
		return out, h.fail("query_access_logs", start, err)
	}
	maxRows := clamp(in.MaxRows, defaultAthenaRows, maxAthenaRows)
	sql, err := prepareAthenaSQL(in.SQL, st, et, maxRows)
	if err != nil {
		return out, h.fail("query_access_logs", start, err)
	}
	out.Query = sql
	out.TimeRange = fmt.Sprintf("%s to %s", st.UTC().Format(time.RFC3339), et.UTC().Format(time.RFC3339))
	out.Warning = warn
	frame, err := h.athenaFrame(ctx, sql, st, et)
	if err != nil {
		return out, h.fail("query_access_logs", start, err)
	}
	for _, f := range frame.Schema.Fields {
		out.Columns = append(out.Columns, f.Name)
	}
	for r := 0; r < frame.RowCount(); r++ {
		row := make([]any, len(frame.Schema.Fields))
		for c := range frame.Schema.Fields {
			v := frame.Cell(c, r)
			if s, ok := v.(string); ok {
				v = truncate(s, maxCellLen)
			}
			row[c] = v
		}
		out.Rows = append(out.Rows, row)
	}
	out.RowCount = len(out.Rows)
	if out.RowCount == maxRows {
		out.Warning = joinWarning(out.Warning, fmt.Sprintf("hit the %d-row limit; aggregate (GROUP BY/count) instead of listing raw rows", maxRows))
	}
	if jsonSize(out) > outputBudget {
		for jsonSize(out) > outputBudget && len(out.Rows) > 1 {
			out.Rows = out.Rows[:len(out.Rows)*4/5]
		}
		out.Truncated = true
		out.Warning = joinWarning(out.Warning, fmt.Sprintf("showing %d of %d rows to fit the size budget; select fewer columns or aggregate", len(out.Rows), out.RowCount))
	}
	h.audit.ToolInvoked("query_access_logs", time.Since(start).Milliseconds(), slog.String("query", sql), slog.Int("result_count", out.RowCount))
	return out, nil
}

func (h *ToolHandlers) athenaFrame(ctx context.Context, sql string, from, to time.Time) (Frame, error) {
	resp, err := h.client.Query(ctx, QueryRequest{From: from, To: to, Queries: []map[string]any{{
		"refId":      "A",
		"datasource": map[string]string{"uid": h.athenaUID},
		"format":     1,
		"rawSQL":     sql,
	}}})
	if err != nil {
		return Frame{}, fmt.Errorf("athena query failed: %w", err)
	}
	res, err := resp.Single("A")
	if err != nil {
		return Frame{}, fmt.Errorf("athena query failed: %w", err)
	}
	if len(res.Frames) == 0 {
		return Frame{}, nil
	}
	return res.Frames[0], nil
}

func (h *ToolHandlers) athenaDatabase(ctx context.Context) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.athenaDB != "" {
		return h.athenaDB, nil
	}
	ds, err := h.client.DataSource(ctx, h.athenaUID)
	if err != nil {
		return "", fmt.Errorf("reading athena datasource: %w", err)
	}
	db, _ := ds.JSONData["database"].(string)
	if db == "" {
		return "", fmt.Errorf("athena datasource %s has no default database", h.athenaUID)
	}
	h.athenaDB = db
	return db, nil
}

func prepareAthenaSQL(raw string, start, end time.Time, maxRows int) (string, error) {
	sql := strings.TrimSpace(raw)
	sql = strings.TrimSpace(strings.TrimSuffix(sql, ";"))
	if sql == "" {
		return "", fmt.Errorf("sql is required")
	}
	scrubbed := sqlStringLiteral.ReplaceAllString(sqlBlockComment.ReplaceAllString(sqlLineComment.ReplaceAllString(sql, " "), " "), "''")
	if strings.Contains(scrubbed, ";") {
		return "", fmt.Errorf("only a single statement is allowed")
	}
	if !sqlLeading.MatchString(scrubbed) {
		return "", fmt.Errorf("only SELECT or WITH queries are allowed")
	}
	if m := sqlForbidden.FindString(scrubbed); m != "" {
		return "", fmt.Errorf("read-only: %q is not allowed", strings.ToUpper(m))
	}
	filter := fmt.Sprintf("day BETWEEN '%s' AND '%s'", start.UTC().Format("2006/01/02"), end.UTC().Format("2006/01/02"))
	sql = strings.ReplaceAll(sql, dayFilterMacro, filter)
	scrubbed = strings.ReplaceAll(scrubbed, dayFilterMacro, filter)
	if !sqlDayPredicate.MatchString(scrubbed) {
		return "", fmt.Errorf("query must filter on the day partition; add WHERE %s (expands to %s)", dayFilterMacro, filter)
	}
	if m := sqlTrailingLimit.FindStringSubmatch(sql); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > maxRows {
			sql = sqlTrailingLimit.ReplaceAllString(sql, fmt.Sprintf("LIMIT %d", maxRows))
		}
	} else {
		sql += fmt.Sprintf(" LIMIT %d", maxRows)
	}
	return sql, nil
}

func escapeSQL(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
