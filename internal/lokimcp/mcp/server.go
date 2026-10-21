// Package mcp provides an MCP (Model Context Protocol) server that exposes
// Loki querying tools for use in Cursor, Claude Code, and other MCP clients.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/grafana"
	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
	"github.com/olusolaa/lokilens/internal/lokimcp/prometheus"
	"github.com/olusolaa/lokilens/internal/lokimcp/safety"
	"github.com/olusolaa/lokilens/internal/lokimcp/tempo"
)

// Option configures optional backends on the MCP server.
type Option func(*serverConfig)

type serverConfig struct {
	metricSource *prometheus.Source
	traceSource  *tempo.Source
	grafanaSrc   *grafana.Source
}

// WithMetrics registers Prometheus metric tools. Passing a nil source is a
// no-op, so callers can wire it unconditionally.
func WithMetrics(src *prometheus.Source) Option {
	return func(c *serverConfig) { c.metricSource = src }
}

func WithGrafana(src *grafana.Source) Option {
	return func(c *serverConfig) { c.grafanaSrc = src }
}

func WithTraces(src *tempo.Source) Option {
	return func(c *serverConfig) { c.traceSource = src }
}

// NewServer creates an MCP server with log tools (Loki) and, when the
// WithMetrics option supplies a source, metric tools (Prometheus). PII
// filtering and audit logging are applied to all tool results.
func NewServer(logSource *loki.Source, piiFilter *safety.PIIFilter, auditLogger *audit.Logger, logger *slog.Logger, opts ...Option) *server.MCPServer {
	var cfg serverConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	metricSource := cfg.metricSource

	s := server.NewMCPServer(
		"lokilens",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithPromptCapabilities(true),
	)

	h := &mcpHandlers{pii: piiFilter, audit: auditLogger, logger: logger}

	if logSource != nil {
		s.AddPrompt(mcp.Prompt{
			Name:        "investigation-guide",
			Description: "Loki investigation guide with multi-step reasoning patterns for log analysis.",
		}, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Description: "Loki investigation reasoning patterns",
				Messages: []mcp.PromptMessage{
					{
						Role: mcp.RoleUser,
						Content: mcp.TextContent{
							Type: "text",
							Text: logSource.Instruction(),
						},
					},
				},
			}, nil
		})
		registerLokiTools(s, logSource, h)
	}

	if metricSource != nil {
		s.AddPrompt(mcp.Prompt{
			Name:        "metrics-investigation-guide",
			Description: "Prometheus investigation guide for metric analysis.",
		}, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Description: "Prometheus investigation reasoning patterns",
				Messages: []mcp.PromptMessage{
					{
						Role: mcp.RoleUser,
						Content: mcp.TextContent{
							Type: "text",
							Text: metricSource.Instruction(),
						},
					},
				},
			}, nil
		})
		registerPrometheusTools(s, metricSource, h)
	}

	if traceSource := cfg.traceSource; traceSource != nil {
		s.AddPrompt(mcp.Prompt{
			Name:        "traces-investigation-guide",
			Description: "Tempo investigation guide for trace analysis with TraceQL.",
		}, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Description: "Tempo investigation reasoning patterns",
				Messages: []mcp.PromptMessage{
					{
						Role: mcp.RoleUser,
						Content: mcp.TextContent{
							Type: "text",
							Text: traceSource.Instruction(),
						},
					},
				},
			}, nil
		})
		registerTempoTools(s, traceSource, h)
	}

	if grafanaSrc := cfg.grafanaSrc; grafanaSrc != nil {
		s.AddPrompt(mcp.Prompt{
			Name:        "aws-investigation-guide",
			Description: "Guide for ALB access logs (Athena), CloudWatch metrics and PostgreSQL query plans via Grafana.",
		}, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Description: "Athena, CloudWatch and PostgreSQL EXPLAIN investigation patterns",
				Messages: []mcp.PromptMessage{
					{
						Role: mcp.RoleUser,
						Content: mcp.TextContent{
							Type: "text",
							Text: grafanaSrc.Instruction(),
						},
					},
				},
			}, nil
		})
		registerGrafanaTools(s, grafanaSrc, h)
	}

	return s
}

// maxResultBytes caps the serialized tool result sent to the MCP client.
// Every byte lands in the model's context and is re-read (and billed) on every
// subsequent turn of the conversation — a result this large means the query
// needs narrowing, not more reading. Per-tool caps (sample logs, series limits,
// label value limits) should make this a rare backstop.
const maxResultBytes = 30_000

type mcpHandlers struct {
	pii    *safety.PIIFilter
	audit  *audit.Logger
	logger *slog.Logger
}

type handlerFunc func(ctx context.Context, args map[string]any) (any, error)

func (h *mcpHandlers) wrap(fn handlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		args := req.GetArguments()
		toolName := req.Params.Name

		result, err := fn(ctx, args)
		durationMS := time.Since(start).Milliseconds()

		if err != nil {
			h.logger.Warn("tool call failed", "tool", toolName, "error", err)
			if h.audit != nil {
				h.audit.ToolFailed(toolName, durationMS, err)
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: mcp.ContentTypeText,
						Text: fmt.Sprintf("Error: %s", err.Error()),
					},
				},
				IsError: true,
			}, nil
		}

		if h.audit != nil {
			h.audit.ToolInvoked(toolName, durationMS)
		}

		text, err := h.marshalAndRedact(toolName, result)
		if err != nil {
			return nil, err
		}

		// Over budget: first try a typed shrink (drops raw evidence, keeps the
		// analysis, stays valid JSON); byte-truncate only as a last resort.
		if len(text) > maxResultBytes {
			if shrunk, ok := loki.ShrinkOversized(result); ok {
				shrunkText, serr := h.marshalAndRedact(toolName, shrunk)
				if serr == nil {
					h.logger.Warn("tool result shrunk to fit size budget", "tool", toolName, "bytes", len(text), "shrunk_bytes", len(shrunkText))
					text = shrunkText
				}
			}
		}
		if len(text) > maxResultBytes {
			h.logger.Warn("tool result truncated", "tool", toolName, "bytes", len(text))
			text = oversizedFallbackJSON(toolName, len(text))
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: mcp.ContentTypeText,
					Text: text,
				},
			},
		}, nil
	}
}

func registerLokiTools(s *server.MCPServer, src *loki.Source, h *mcpHandlers) {
	handlers := src.Handlers()

	s.AddTool(
		mcp.NewTool("query_logs",
			mcp.WithDescription("Fetch raw log lines from Loki with pattern analysis. Returns logs, top_patterns (grouped similar lines with counts/percentages), unique_labels distribution. Use for actual log messages, error details, stack traces."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("logql", mcp.Required(), mcp.Description("LogQL query string (e.g. {service=\"payments\"} |= \"error\")")),
			mcp.WithString("start_time", mcp.Description("Start time — relative like '10m ago', '2h ago', '1d ago' or RFC3339. Defaults to 1h ago")),
			mcp.WithString("end_time", mcp.Description("End time — relative like 'now' or RFC3339. Defaults to now")),
			mcp.WithNumber("limit", mcp.Description("Max log lines (1-500, default 100)")),
			mcp.WithString("direction", mcp.Description("Sort: 'backward' (newest first, default) or 'forward' (oldest first)")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			input := loki.QueryLogsInput{
				LogQL:     stringArg(args, "logql"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
				Limit:     intArg(args, "limit"),
				Direction: stringArg(args, "direction"),
			}
			return handlers.QueryLogs(ctx, input)
		}),
	)

	s.AddTool(
		mcp.NewTool("get_labels",
			mcp.WithDescription("List all label names in Loki (e.g. service, level, namespace). Call FIRST to discover which labels exist before building queries."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("start_time", mcp.Description("Start time. Defaults to 6h ago")),
			mcp.WithString("end_time", mcp.Description("End time. Defaults to now")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			input := loki.GetLabelsInput{
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
			}
			return handlers.GetLabels(ctx, input)
		}),
	)

	s.AddTool(
		mcp.NewTool("get_label_values",
			mcp.WithDescription("Get values for a specific label (e.g. service names, log levels). Essential for building correct LogQL queries. Returns up to 'limit' values (default 50) plus total_values; use 'contains' to search within high-cardinality labels instead of listing everything."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("label_name", mcp.Required(), mcp.Description("The label to get values for (e.g. 'service' or 'level')")),
			mcp.WithString("contains", mcp.Description("Case-insensitive substring filter (e.g. 'pay' to find payment-related services)")),
			mcp.WithString("start_time", mcp.Description("Start time. Defaults to 6h ago")),
			mcp.WithString("end_time", mcp.Description("End time. Defaults to now")),
			mcp.WithNumber("limit", mcp.Description("Max values to return (1-200, default 50)")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			input := loki.GetLabelValuesInput{
				LabelName: stringArg(args, "label_name"),
				Contains:  stringArg(args, "contains"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
				Limit:     intArg(args, "limit"),
			}
			return handlers.GetLabelValues(ctx, input)
		}),
	)

	s.AddTool(
		mcp.NewTool("query_stats",
			mcp.WithDescription("Run aggregation queries for counts, rates, and trends over time. Returns time-series data with summaries: total, avg_per_minute, peak, peak_time, trend direction. Use for 'how many errors?', 'error rate trend', 'is it getting worse?'."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("logql", mcp.Required(), mcp.Description("LogQL metric query (e.g. rate({service=\"payments\"} |= \"error\" [5m]))")),
			mcp.WithString("start_time", mcp.Required(), mcp.Description("Start time — relative like '10m ago', '2h ago' or RFC3339")),
			mcp.WithString("end_time", mcp.Description("End time — relative like 'now' or RFC3339. Defaults to now")),
			mcp.WithString("step", mcp.Description("Resolution step (e.g. '1m', '5m'). Auto-selected if empty.")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			input := loki.QueryStatsInput{
				LogQL:     stringArg(args, "logql"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
				Step:      stringArg(args, "step"),
			}
			return handlers.QueryStats(ctx, input)
		}),
	)

	h.logger.Info("registered Loki MCP tools", "count", 4)
}

// marshalAndRedact serializes a tool result and applies PII redaction.
func (h *mcpHandlers) marshalAndRedact(toolName string, result any) (string, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshaling result: %w", err)
	}
	text := string(data)
	if h.pii != nil {
		redacted, count := h.pii.RedactWithCount(text)
		if count > 0 {
			h.logger.Info("pii redacted from MCP result", "tool", toolName, "patterns", count)
			if h.audit != nil {
				h.audit.PIIRedacted("mcp", toolName, count)
			}
		}
		text = redacted
	}
	return text, nil
}

// oversizedFallbackJSON returns a small, valid JSON payload for the last-resort
// size-budget path. Tool responses are normally JSON, so returning partial JSON
// here makes the caller's success path harder to consume than the error itself.
func oversizedFallbackJSON(toolName string, originalBytes int) string {
	payload := struct {
		Truncated     bool   `json:"truncated"`
		Warning       string `json:"warning"`
		Tool          string `json:"tool,omitempty"`
		OriginalBytes int    `json:"original_bytes"`
	}{
		Truncated:     true,
		Warning:       "TRUNCATED: result exceeded 30KB; narrow the query with a shorter time range, tighter label/line filters, a lower limit, or query_stats aggregations",
		Tool:          toolName,
		OriginalBytes: originalBytes,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return `{"truncated":true,"warning":"TRUNCATED: result exceeded 30KB; narrow the query and retry"}`
	}
	return string(data)
}

// truncateUTF8 cuts s to at most maxBytes without splitting a UTF-8 rune.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

func registerPrometheusTools(s *server.MCPServer, src *prometheus.Source, h *mcpHandlers) {
	handlers := src.Handlers()

	s.AddTool(
		mcp.NewTool("list_metrics",
			mcp.WithDescription("List metric names in Prometheus. Call FIRST to discover which metrics exist before building PromQL. Optionally filter with a series selector."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("match", mcp.Description("Optional series selector, e.g. {job=\"node\"}")),
			mcp.WithString("start_time", mcp.Description("Start time. Defaults to 6h ago")),
			mcp.WithString("end_time", mcp.Description("End time. Defaults to now")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.ListMetrics(ctx, prometheus.ListMetricsInput{
				Match:     stringArg(args, "match"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
			})
		}),
	)

	s.AddTool(
		mcp.NewTool("get_metric_metadata",
			mcp.WithDescription("Get TYPE, HELP, and unit for a metric (or all metrics). Use to understand what a metric measures before querying."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("metric", mcp.Description("Metric name. Empty returns metadata for all metrics.")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.GetMetricMetadata(ctx, prometheus.GetMetricMetadataInput{
				Metric: stringArg(args, "metric"),
			})
		}),
	)

	s.AddTool(
		mcp.NewTool("get_metric_label_values",
			mcp.WithDescription("Get all values for a label (e.g. instance, job, service). Essential for building correct PromQL selectors."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("label_name", mcp.Required(), mcp.Description("Label to get values for, e.g. 'instance' or 'job'")),
			mcp.WithString("match", mcp.Description("Optional series selector to scope values")),
			mcp.WithString("start_time", mcp.Description("Start time. Defaults to 6h ago")),
			mcp.WithString("end_time", mcp.Description("End time. Defaults to now")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.GetMetricLabelValues(ctx, prometheus.GetMetricLabelValuesInput{
				LabelName: stringArg(args, "label_name"),
				Match:     stringArg(args, "match"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
			})
		}),
	)

	s.AddTool(
		mcp.NewTool("query_metrics_instant",
			mcp.WithDescription("Evaluate a PromQL instant query — the current value(s). Use for 'what is X right now'."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("promql", mcp.Required(), mcp.Description("PromQL query, e.g. sum(rate(http_requests_total[5m]))")),
			mcp.WithString("time", mcp.Description("Evaluation time — 'now' or RFC3339. Defaults to now")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.QueryInstant(ctx, prometheus.QueryInstantInput{
				PromQL: stringArg(args, "promql"),
				Time:   stringArg(args, "time"),
			})
		}),
	)

	s.AddTool(
		mcp.NewTool("query_metrics_range",
			mcp.WithDescription("Evaluate a PromQL range query over time. Use for trends: 'is CPU climbing?', 'error rate over the last hour'. Step is auto-bounded to keep results small."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("promql", mcp.Required(), mcp.Description("PromQL query, e.g. rate(http_requests_total[5m])")),
			mcp.WithString("start_time", mcp.Required(), mcp.Description("Start time — relative like '1h ago' or RFC3339")),
			mcp.WithString("end_time", mcp.Description("End time — 'now' or RFC3339. Defaults to now")),
			mcp.WithString("step", mcp.Description("Resolution step (e.g. 30s, 1m). Auto-selected if empty.")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.QueryRange(ctx, prometheus.QueryRangeInput{
				PromQL:    stringArg(args, "promql"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
				Step:      stringArg(args, "step"),
			})
		}),
	)

	h.logger.Info("registered Prometheus MCP tools", "count", 5)
}

func registerTempoTools(s *server.MCPServer, src *tempo.Source, h *mcpHandlers) {
	handlers := src.Handlers()

	s.AddTool(
		mcp.NewTool("search_traces",
			mcp.WithDescription("Search Tempo traces with TraceQL. Returns trace summaries (root service/name, duration, per-service span and error counts, up to 3 matching spans). Use to find slow or failing requests, then call get_trace on a trace_id."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("traceql", mcp.Required(), mcp.Description("TraceQL query, e.g. {resource.service.name=\"wallet-service\" && kind=server && duration>1s} or {status=error}")),
			mcp.WithString("start_time", mcp.Description("Start time — relative like '1h ago' or RFC3339. Defaults to 1h ago")),
			mcp.WithString("end_time", mcp.Description("End time — 'now' or RFC3339. Defaults to now")),
			mcp.WithNumber("limit", mcp.Description("Max traces to return (default 20, max 50)")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.SearchTraces(ctx, tempo.SearchTracesInput{
				TraceQL:   stringArg(args, "traceql"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
				Limit:     intArg(args, "limit"),
			})
		}),
	)

	s.AddTool(
		mcp.NewTool("get_trace",
			mcp.WithDescription("Fetch one trace by ID as a compact span tree: per-service self time (time not spent waiting on child spans; parallel calls can make the total exceed the trace duration) and error counts, all error spans, and spans ordered by start with depth, offset and duration. Large traces keep roots, errors and the slowest spans."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("trace_id", mcp.Required(), mcp.Description("Trace ID (hex), from search_traces or a log line's trace_id")),
			mcp.WithString("service", mcp.Description("Only list spans from this service (errors and summary still cover the whole trace)")),
			mcp.WithNumber("min_duration_ms", mcp.Description("Hide spans faster than this (roots and errors always kept)")),
			mcp.WithNumber("max_spans", mcp.Description("Max spans to list (default 60, max 300)")),
			mcp.WithString("start_time", mcp.Description("Optional search window start; speeds up lookups of old traces")),
			mcp.WithString("end_time", mcp.Description("Optional search window end")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.GetTrace(ctx, tempo.GetTraceInput{
				TraceID:       stringArg(args, "trace_id"),
				Service:       stringArg(args, "service"),
				MinDurationMS: floatArg(args, "min_duration_ms"),
				MaxSpans:      intArg(args, "max_spans"),
				StartTime:     stringArg(args, "start_time"),
				EndTime:       stringArg(args, "end_time"),
			})
		}),
	)

	s.AddTool(
		mcp.NewTool("get_trace_tags",
			mcp.WithDescription("List attribute names available for TraceQL, grouped by scope (resource, span, intrinsic)."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("scope", mcp.Description("Optional scope filter: resource, span, intrinsic")),
			mcp.WithString("start_time", mcp.Description("Start time. Defaults to 1h ago")),
			mcp.WithString("end_time", mcp.Description("End time. Defaults to now")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.GetTraceTags(ctx, tempo.GetTraceTagsInput{
				Scope:     stringArg(args, "scope"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
			})
		}),
	)

	s.AddTool(
		mcp.NewTool("get_trace_tag_values",
			mcp.WithDescription("List values of a scoped trace attribute, e.g. resource.service.name or span.http.route. Use to build correct TraceQL filters."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("tag", mcp.Required(), mcp.Description("Scoped attribute, e.g. resource.service.name, span.rpc.method, name")),
			mcp.WithString("traceql", mcp.Description("Optional TraceQL to scope values, e.g. {resource.service.name=\"wallet-service\"}")),
			mcp.WithString("start_time", mcp.Description("Start time. Defaults to 1h ago")),
			mcp.WithString("end_time", mcp.Description("End time. Defaults to now")),
			mcp.WithNumber("limit", mcp.Description("Max values to return (default 100, max 1000)")),
		),
		h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
			return handlers.GetTraceTagValues(ctx, tempo.GetTraceTagValuesInput{
				Tag:       stringArg(args, "tag"),
				TraceQL:   stringArg(args, "traceql"),
				StartTime: stringArg(args, "start_time"),
				EndTime:   stringArg(args, "end_time"),
				Limit:     intArg(args, "limit"),
			})
		}),
	)

	h.logger.Info("registered Tempo MCP tools", "count", 4)
}

func registerGrafanaTools(s *server.MCPServer, src *grafana.Source, h *mcpHandlers) {
	handlers := src.Handlers()
	count := 0

	if src.HasAthena() {
		s.AddTool(
			mcp.NewTool("describe_access_logs",
				mcp.WithDescription("List ALB access-log tables and their columns (Athena via Grafana). Call before query_access_logs."),
				mcp.WithReadOnlyHintAnnotation(true),
				mcp.WithString("table", mcp.Description("Optional table name to describe only that table")),
			),
			h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
				return handlers.DescribeAccessLogs(ctx, grafana.DescribeInput{Table: stringArg(args, "table")})
			}),
		)
		s.AddTool(
			mcp.NewTool("query_access_logs",
				mcp.WithDescription("Run a read-only Presto SQL query over ALB access logs in Athena. Must filter on the day partition: put $__dayFilter in WHERE and it expands to the start_time..end_time days. Prefer GROUP BY aggregates; raw rows are capped."),
				mcp.WithReadOnlyHintAnnotation(true),
				mcp.WithString("sql", mcp.Required(), mcp.Description("SELECT/WITH query, e.g. SELECT elb_status_code, count(*) FROM user_gateway_alb_access_logs WHERE $__dayFilter AND time >= '2026-10-14T10:00:00' GROUP BY 1")),
				mcp.WithString("start_time", mcp.Description("Window start — relative like '6h ago' or RFC3339. Defaults to 1h ago")),
				mcp.WithString("end_time", mcp.Description("Window end. Defaults to now")),
				mcp.WithNumber("max_rows", mcp.Description("Row cap (default 100, max 500)")),
			),
			h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
				return handlers.QueryAccessLogs(ctx, grafana.AthenaQueryInput{
					SQL:       stringArg(args, "sql"),
					StartTime: stringArg(args, "start_time"),
					EndTime:   stringArg(args, "end_time"),
					MaxRows:   intArg(args, "max_rows"),
				})
			}),
		)
		count += 2
	}

	if src.HasCloudWatch() {
		s.AddTool(
			mcp.NewTool("list_cloudwatch_metrics",
				mcp.WithDescription("List CloudWatch metric names in a namespace (e.g. AWS/RDS, AWS/ApplicationELB, AWS/SQS). Omit namespace to list namespaces."),
				mcp.WithReadOnlyHintAnnotation(true),
				mcp.WithString("namespace", mcp.Description("CloudWatch namespace, e.g. AWS/RDS")),
				mcp.WithString("region", mcp.Description("AWS region. Defaults to the datasource region")),
			),
			h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
				return handlers.ListCloudWatchMetrics(ctx, grafana.ListMetricsInput{
					Namespace: stringArg(args, "namespace"),
					Region:    stringArg(args, "region"),
				})
			}),
		)
		s.AddTool(
			mcp.NewTool("get_cloudwatch_dimensions",
				mcp.WithDescription("List dimension keys for a CloudWatch metric, or the values of one key (e.g. DBInstanceIdentifier, LoadBalancer, QueueName)."),
				mcp.WithReadOnlyHintAnnotation(true),
				mcp.WithString("namespace", mcp.Required(), mcp.Description("CloudWatch namespace")),
				mcp.WithString("metric", mcp.Required(), mcp.Description("Metric name")),
				mcp.WithString("key", mcp.Description("Dimension key to list values for. Omit to list keys")),
				mcp.WithString("region", mcp.Description("AWS region. Defaults to the datasource region")),
				mcp.WithNumber("limit", mcp.Description("Max values (default 100, max 1000)")),
			),
			h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
				return handlers.GetCloudWatchDimensions(ctx, grafana.DimensionsInput{
					Namespace: stringArg(args, "namespace"),
					Metric:    stringArg(args, "metric"),
					Key:       stringArg(args, "key"),
					Region:    stringArg(args, "region"),
					Limit:     intArg(args, "limit"),
				})
			}),
		)
		s.AddTool(
			mcp.NewTool("query_cloudwatch",
				mcp.WithDescription("Query a CloudWatch metric over time with trend summaries. Period auto-bounds to keep results small. Count metrics publish nothing while zero."),
				mcp.WithReadOnlyHintAnnotation(true),
				mcp.WithString("namespace", mcp.Required(), mcp.Description("CloudWatch namespace, e.g. AWS/RDS")),
				mcp.WithString("metric", mcp.Required(), mcp.Description("Metric name, e.g. CommitLatency")),
				mcp.WithObject("dimensions", mcp.Description("Dimension name to value, e.g. {\"DBInstanceIdentifier\":\"grey-aurora-db-transaction-prod-instance\"}. Use \"*\" to match all")),
				mcp.WithString("statistic", mcp.Description("Average (default), Sum, Maximum, Minimum, SampleCount, or a percentile like p99")),
				mcp.WithNumber("period", mcp.Description("Seconds per point, multiple of 60. Auto-raised to stay under the point cap")),
				mcp.WithString("start_time", mcp.Description("Start — relative like '6h ago' or RFC3339. Defaults to 1h ago")),
				mcp.WithString("end_time", mcp.Description("End. Defaults to now")),
				mcp.WithString("region", mcp.Description("AWS region. Defaults to the datasource region")),
			),
			h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
				return handlers.QueryCloudWatch(ctx, grafana.CloudWatchQueryInput{
					Namespace:  stringArg(args, "namespace"),
					Metric:     stringArg(args, "metric"),
					Dimensions: stringMapArg(args, "dimensions"),
					Statistic:  stringArg(args, "statistic"),
					Period:     intArg(args, "period"),
					StartTime:  stringArg(args, "start_time"),
					EndTime:    stringArg(args, "end_time"),
					Region:     stringArg(args, "region"),
				})
			}),
		)
		count += 3
	}

	if src.HasPostgres() {
		s.AddTool(
			mcp.NewTool("explain_query",
				mcp.WithDescription("Show the PostgreSQL query plan (EXPLAIN, never ANALYZE) for one SELECT/WITH/VALUES statement. The query is not executed and no rows are returned. Databases: "+strings.Join(handlers.PostgresDatabases(), ", ")),
				mcp.WithReadOnlyHintAnnotation(true),
				mcp.WithString("database", mcp.Required(), mcp.Description("Database name from the list in the tool description; prefer readers")),
				mcp.WithString("query", mcp.Required(), mcp.Description("A single SELECT, WITH or VALUES statement. $1-style placeholders work on PostgreSQL 16; use literals on audit and grey-db-prod")),
			),
			h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
				return handlers.ExplainQuery(ctx, grafana.ExplainInput{
					Database: stringArg(args, "database"),
					Query:    stringArg(args, "query"),
				})
			}),
		)
		count++
	}

	h.logger.Info("registered Grafana MCP tools", "count", count)
}

func stringMapArg(args map[string]any, key string) map[string]string {
	out := map[string]string{}
	switch v := args[key].(type) {
	case map[string]any:
		for k, val := range v {
			out[k] = fmt.Sprint(val)
		}
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(v), &m) == nil {
			for k, val := range m {
				out[k] = fmt.Sprint(val)
			}
		}
	}
	return out
}

func floatArg(args map[string]any, key string) float64 {
	switch v := args[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}

func stringArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func intArg(args map[string]any, key string) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}
