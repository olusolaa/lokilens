// Package mcp provides an MCP (Model Context Protocol) server that exposes
// Loki querying tools for use in Cursor, Claude Code, and other MCP clients.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
	"github.com/olusolaa/lokilens/internal/lokimcp/safety"
)

// NewServer creates an MCP server with Loki tools only.
// PII filtering and audit logging are applied to all tool results.
func NewServer(source *loki.Source, piiFilter *safety.PIIFilter, auditLogger *audit.Logger, logger *slog.Logger) *server.MCPServer {
	s := server.NewMCPServer(
		"lokilens",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithPromptCapabilities(true),
	)

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
						Text: source.Instruction(),
					},
				},
			},
		}, nil
	})

	h := &mcpHandlers{pii: piiFilter, audit: auditLogger, logger: logger}
	registerLokiTools(s, source, h)
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
