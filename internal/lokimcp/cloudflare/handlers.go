package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
)

const (
	defaultLimit      = 100
	maxLimit          = 1000
	datasetGroups     = "httpRequestsAdaptiveGroups"
	sampledNote       = "Counts in adaptive datasets are sampled. In httpRequestsAdaptiveGroups, include avg { sampleInterval } in fields to see the sampling rate."
	maxFilterNesting  = 8
	datetimeGeqKey    = "datetime_geq"
	datetimeLeqKey    = "datetime_leq"
	datetimeOrderDesc = "datetime_DESC"
	countOrderDesc    = "count_DESC"
)

var (
	datasets     = []string{"httpRequestsAdaptive", "httpRequestsAdaptiveGroups", "firewallEventsAdaptive"}
	filterKeyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	orderByRe    = regexp.MustCompile(`^[A-Za-z0-9_]+_(ASC|DESC)$`)
	fieldsCharRe = regexp.MustCompile(`^[A-Za-z0-9_ \t\n{}]+$`)
)

type QueryCloudflareInput struct {
	Zone      string
	Dataset   string
	StartTime string
	EndTime   string
	Fields    string
	Filter    map[string]any
	OrderBy   []string
	Limit     int
}

type QueryCloudflareOutput struct {
	Zone     string           `json:"zone"`
	Dataset  string           `json:"dataset"`
	Query    string           `json:"query"`
	Rows     []map[string]any `json:"rows"`
	RowCount int              `json:"row_count"`
	Note     string           `json:"note"`
}

type ToolHandlers struct {
	client   Client
	zones    map[string]string
	maxRange time.Duration
	audit    *audit.Logger
}

func NewToolHandlers(client Client, zones map[string]string, maxRange time.Duration, auditLogger *audit.Logger) *ToolHandlers {
	if maxRange <= 0 {
		maxRange = 168 * time.Hour
	}
	return &ToolHandlers{client: client, zones: zones, maxRange: maxRange, audit: auditLogger}
}

func (h *ToolHandlers) fail(tool string, start time.Time, err error) error {
	h.audit.ToolFailed(tool, time.Since(start).Milliseconds(), err)
	return err
}

func (h *ToolHandlers) zoneNames() []string {
	names := make([]string, 0, len(h.zones))
	for n := range h.zones {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (h *ToolHandlers) resolveRange(startIn, endIn string) (time.Time, time.Time, error) {
	st, err := loki.ParseTimeOrDefault(startIn, time.Hour)
	if err != nil {
		return st, st, err
	}
	et, err := loki.ParseTimeOrDefault(endIn, 0)
	if err != nil {
		return st, et, err
	}
	if et.Before(st) {
		st, et = et, st
	}
	if et.Sub(st) > h.maxRange {
		return st, et, fmt.Errorf("time range %s exceeds the maximum of %s; narrow start/end", et.Sub(st).Round(time.Second), h.maxRange)
	}
	return st.UTC(), et.UTC(), nil
}

func (h *ToolHandlers) QueryCloudflare(ctx context.Context, in QueryCloudflareInput) (QueryCloudflareOutput, error) {
	start := time.Now()
	out := QueryCloudflareOutput{Zone: in.Zone, Dataset: in.Dataset, Rows: []map[string]any{}, Note: sampledNote}

	tag, ok := h.zones[in.Zone]
	if !ok {
		return out, h.fail("query_cloudflare", start, fmt.Errorf("unknown zone %q; configured zones: %s", in.Zone, strings.Join(h.zoneNames(), ", ")))
	}
	if !validDataset(in.Dataset) {
		return out, h.fail("query_cloudflare", start, fmt.Errorf("unknown dataset %q; must be one of: %s", in.Dataset, strings.Join(datasets, ", ")))
	}
	if err := validateFields(in.Fields); err != nil {
		return out, h.fail("query_cloudflare", start, err)
	}
	limit := in.Limit
	switch {
	case limit == 0:
		limit = defaultLimit
	case limit < 0 || limit > maxLimit:
		return out, h.fail("query_cloudflare", start, fmt.Errorf("limit must be between 1 and %d", maxLimit))
	}
	orderBy := in.OrderBy
	if len(orderBy) == 0 {
		if in.Dataset == datasetGroups {
			orderBy = []string{countOrderDesc}
		} else {
			orderBy = []string{datetimeOrderDesc}
		}
	}
	for _, o := range orderBy {
		if !orderByRe.MatchString(o) {
			return out, h.fail("query_cloudflare", start, fmt.Errorf("invalid order_by %q; expected <field>_ASC or <field>_DESC", o))
		}
	}
	st, et, err := h.resolveRange(in.StartTime, in.EndTime)
	if err != nil {
		return out, h.fail("query_cloudflare", start, err)
	}
	filter, err := buildFilterLiteral(in.Filter, st, et)
	if err != nil {
		return out, h.fail("query_cloudflare", start, err)
	}

	out.Query = fmt.Sprintf(`{ viewer { zones(filter: {zoneTag: "%s"}) { %s(limit: %d, filter: %s, orderBy: [%s]) { %s } } } }`,
		tag, in.Dataset, limit, filter, strings.Join(orderBy, ", "), strings.TrimSpace(in.Fields))

	resp, err := h.client.Query(ctx, out.Query)
	if err != nil {
		return out, h.fail("query_cloudflare", start, fmt.Errorf("cloudflare query failed: %w", err))
	}
	rows, err := extractRows(resp, in.Dataset)
	if err != nil {
		return out, h.fail("query_cloudflare", start, err)
	}
	out.Rows = rows
	out.RowCount = len(rows)
	h.audit.ToolInvoked("query_cloudflare", time.Since(start).Milliseconds(), slog.String("zone", in.Zone), slog.String("dataset", in.Dataset), slog.Int("result_count", out.RowCount))
	return out, nil
}

func validDataset(d string) bool {
	for _, v := range datasets {
		if v == d {
			return true
		}
	}
	return false
}

func validateFields(fields string) error {
	if strings.TrimSpace(fields) == "" {
		return fmt.Errorf("fields is required, e.g. \"count dimensions { edgeResponseStatus }\"")
	}
	if !fieldsCharRe.MatchString(fields) {
		return fmt.Errorf("fields may only contain letters, digits, underscores, whitespace and braces")
	}
	depth := 0
	for _, r := range fields {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return fmt.Errorf("fields has unbalanced braces")
			}
		}
	}
	if depth != 0 {
		return fmt.Errorf("fields has unbalanced braces")
	}
	return nil
}

func buildFilterLiteral(filter map[string]any, st, et time.Time) (string, error) {
	merged := make(map[string]any, len(filter)+2)
	for k, v := range filter {
		if k == datetimeGeqKey || k == datetimeLeqKey {
			return "", fmt.Errorf("filter must not set %s; use start and end", k)
		}
		merged[k] = v
	}
	merged[datetimeGeqKey] = st.UTC().Format(time.RFC3339)
	merged[datetimeLeqKey] = et.UTC().Format(time.RFC3339)
	return objectLiteral(merged, 0)
}

func objectLiteral(obj map[string]any, depth int) (string, error) {
	if depth > maxFilterNesting {
		return "", fmt.Errorf("filter nesting exceeds %d levels", maxFilterNesting)
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		if !filterKeyRe.MatchString(k) {
			return "", fmt.Errorf("invalid filter key %q", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, err := valueLiteral(obj[k], depth, true)
		if err != nil {
			return "", fmt.Errorf("filter %q: %w", k, err)
		}
		parts = append(parts, k+": "+v)
	}
	return "{" + strings.Join(parts, ", ") + "}", nil
}

func valueLiteral(v any, depth int, allowArray bool) (string, error) {
	switch x := v.(type) {
	case string:
		return quote(x), nil
	case bool:
		return strconv.FormatBool(x), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case json.Number:
		return x.String(), nil
	case map[string]any:
		return objectLiteral(x, depth+1)
	case []any:
		if !allowArray {
			return "", fmt.Errorf("nested arrays are not supported")
		}
		items := make([]string, 0, len(x))
		for _, e := range x {
			s, err := valueLiteral(e, depth, false)
			if err != nil {
				return "", err
			}
			items = append(items, s)
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	}
	return "", fmt.Errorf("unsupported value type %T; use string, number, bool, array or object", v)
}

var quoteReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)

func quote(s string) string {
	return `"` + quoteReplacer.Replace(s) + `"`
}

func extractRows(resp *Response, dataset string) ([]map[string]any, error) {
	var data zonesData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("decoding cloudflare response: %w", err)
	}
	if len(data.Viewer.Zones) == 0 {
		return nil, fmt.Errorf("cloudflare returned no zone; the token may lack access to it")
	}
	raw, ok := data.Viewer.Zones[0][dataset]
	if !ok {
		return nil, fmt.Errorf("cloudflare response missing dataset %q", dataset)
	}
	rows := []map[string]any{}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("decoding %s rows: %w", dataset, err)
	}
	return rows, nil
}
