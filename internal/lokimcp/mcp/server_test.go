package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
	"github.com/olusolaa/lokilens/internal/lokimcp/safety"
)

func TestNewServer_Loki(t *testing.T) {
	logger := slog.Default()
	v := safety.NewValidator(500)
	al := audit.New(logger)
	src := loki.NewSource(nil, v, al)

	s := NewServer(src, safety.NewPIIFilter(), al, logger)
	if s == nil {
		t.Fatal("expected non-nil server")
	}

	tools := listTools(t, s)
	assertToolNames(t, tools, []string{"query_logs", "get_labels", "get_label_values", "query_stats"})
}

func TestNewServer_LokiToolSchemas(t *testing.T) {
	logger := slog.Default()
	v := safety.NewValidator(500)
	al := audit.New(logger)
	src := loki.NewSource(nil, v, al)

	s := NewServer(src, safety.NewPIIFilter(), al, logger)
	tools := listTools(t, s)

	// Verify query_logs has required field "logql"
	ql := findTool(t, tools, "query_logs")
	assertRequired(t, ql, "logql")
	assertHasProperty(t, ql, "start_time")
	assertHasProperty(t, ql, "end_time")
	assertHasProperty(t, ql, "limit")
	assertHasProperty(t, ql, "direction")

	// Verify get_label_values has required field "label_name"
	glv := findTool(t, tools, "get_label_values")
	assertRequired(t, glv, "label_name")

	// Verify query_stats has required fields
	qs := findTool(t, tools, "query_stats")
	assertRequired(t, qs, "logql")
	assertRequired(t, qs, "start_time")
}

func TestNewServer_ToolAnnotations(t *testing.T) {
	logger := slog.Default()
	v := safety.NewValidator(500)
	al := audit.New(logger)
	src := loki.NewSource(nil, v, al)

	s := NewServer(src, safety.NewPIIFilter(), al, logger)
	tools := listTools(t, s)

	for _, tool := range tools {
		if tool.Annotations.ReadOnlyHint == nil || !*tool.Annotations.ReadOnlyHint {
			t.Errorf("tool %q should have ReadOnlyHint=true", tool.Name)
		}
	}
}

func TestStringArg(t *testing.T) {
	args := map[string]any{"key": "value", "num": 42}
	if got := stringArg(args, "key"); got != "value" {
		t.Errorf("expected 'value', got %q", got)
	}
	if got := stringArg(args, "missing"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
	if got := stringArg(args, "num"); got != "" {
		t.Errorf("expected empty for non-string, got %q", got)
	}
}

func TestIntArg(t *testing.T) {
	args := map[string]any{"f": float64(42), "i": 10, "s": "nope"}
	if got := intArg(args, "f"); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}
	if got := intArg(args, "i"); got != 10 {
		t.Errorf("expected 10, got %d", got)
	}
	if got := intArg(args, "s"); got != 0 {
		t.Errorf("expected 0 for string, got %d", got)
	}
	if got := intArg(args, "missing"); got != 0 {
		t.Errorf("expected 0 for missing, got %d", got)
	}
}

func TestMcpHandler_Error(t *testing.T) {
	logger := slog.Default()
	h := &mcpHandlers{pii: safety.NewPIIFilter(), audit: audit.New(logger), logger: logger}
	handler := h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
		return nil, context.DeadlineExceeded
	})

	result, err := handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("expected nil error (errors returned in result), got %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true")
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in error result")
	}
}

func TestMcpHandler_Success(t *testing.T) {
	logger := slog.Default()
	h := &mcpHandlers{pii: safety.NewPIIFilter(), audit: audit.New(logger), logger: logger}
	handler := h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
		return map[string]string{"status": "ok"}, nil
	})

	result, err := handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Error("expected IsError=false")
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content")
	}
	text := result.Content[0].(mcp.TextContent).Text
	var parsed map[string]string
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("expected JSON content, got %q", text)
	}
	if parsed["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", parsed["status"])
	}
}

func TestMcpHandler_PIIRedaction(t *testing.T) {
	logger := slog.Default()
	h := &mcpHandlers{pii: safety.NewPIIFilter(), audit: audit.New(logger), logger: logger}
	handler := h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
		return map[string]string{"message": "user john@example.com logged in from 203.0.113.5"}, nil
	})

	result, err := handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if json.Valid([]byte(text)) {
		if contains(text, "john@example.com") {
			t.Error("email was not redacted from MCP result")
		}
		if contains(text, "203.0.113.5") {
			t.Error("public IP was not redacted from MCP result")
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && json.Valid([]byte(s)) && len(substr) > 0 && stringContains(s, substr)
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// --- test helpers ---

func listTools(t *testing.T, s *server.MCPServer) []mcp.Tool {
	t.Helper()
	// Use the server's HandleMessage to call tools/list
	ctx := context.Background()

	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]any{},
	}
	reqBytes, _ := json.Marshal(req)

	respMsg := s.HandleMessage(ctx, json.RawMessage(reqBytes))

	respBytes, err := json.Marshal(respMsg)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var resp struct {
		Result struct {
			Tools []mcp.Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("failed to parse tools/list response: %v\nraw: %s", err, respBytes)
	}
	return resp.Result.Tools
}

func assertToolNames(t *testing.T, tools []mcp.Tool, expected []string) {
	t.Helper()
	if len(tools) != len(expected) {
		t.Fatalf("expected %d tools, got %d", len(expected), len(tools))
	}
	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("missing tool %q", name)
		}
	}
}

func findTool(t *testing.T, tools []mcp.Tool, name string) mcp.Tool {
	t.Helper()
	for _, tool := range tools {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %q not found", name)
	return mcp.Tool{}
}

func assertRequired(t *testing.T, tool mcp.Tool, field string) {
	t.Helper()
	for _, r := range tool.InputSchema.Required {
		if r == field {
			return
		}
	}
	t.Errorf("tool %q: expected %q to be required", tool.Name, field)
}

func assertHasProperty(t *testing.T, tool mcp.Tool, field string) {
	t.Helper()
	if _, ok := tool.InputSchema.Properties[field]; !ok {
		t.Errorf("tool %q: expected property %q", tool.Name, field)
	}
}

func TestMcpHandler_TruncatesOversizedResult(t *testing.T) {
	logger := slog.Default()
	h := &mcpHandlers{pii: safety.NewPIIFilter(), audit: audit.New(logger), logger: logger}

	big := make([]string, 0, 5000)
	for i := 0; i < 5000; i++ {
		big = append(big, "a-fairly-long-log-line-that-repeats-itself-endlessly")
	}
	handler := h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
		return map[string]any{"lines": big}, nil
	})

	result, err := handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	// cap + truncation notice, with slack for the appended marker
	if len(text) > maxResultBytes+300 {
		t.Errorf("expected result capped near %d bytes, got %d", maxResultBytes, len(text))
	}
	if !stringContains(text, "TRUNCATED") {
		t.Error("expected truncation notice in oversized result")
	}
}

func TestMcpHandler_SmallResultNotTruncated(t *testing.T) {
	logger := slog.Default()
	h := &mcpHandlers{pii: safety.NewPIIFilter(), audit: audit.New(logger), logger: logger}
	handler := h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
		return map[string]string{"status": "ok"}, nil
	})

	result, err := handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if stringContains(text, "TRUNCATED") {
		t.Error("small result should not be truncated")
	}
}

func TestNewServer_GetLabelValuesSchemaHasCapParams(t *testing.T) {
	logger := slog.Default()
	v := safety.NewValidator(500)
	al := audit.New(logger)
	src := loki.NewSource(nil, v, al)

	s := NewServer(src, safety.NewPIIFilter(), al, logger)
	tools := listTools(t, s)

	glv := findTool(t, tools, "get_label_values")
	assertHasProperty(t, glv, "contains")
	assertHasProperty(t, glv, "limit")
}

func TestMcpHandler_ShrinksKnownTypeToValidJSON(t *testing.T) {
	logger := slog.Default()
	h := &mcpHandlers{pii: safety.NewPIIFilter(), audit: audit.New(logger), logger: logger}

	// A QueryLogsOutput whose raw logs blow the 30KB budget: the wrapper must
	// shrink it (drop logs, keep analysis) rather than byte-truncate it.
	big := loki.QueryLogsOutput{
		TopPatterns: []loki.ErrorPattern{{Pattern: "connection timeout to <*>", Count: 3000, Pct: 100, Sample: "connection timeout to 10.0.0.1"}},
	}
	for i := 0; i < 3000; i++ {
		big.Logs = append(big.Logs, loki.LogEntry{
			Timestamp: "2026-07-05T10:00:00.000Z",
			Line:      "connection timeout to 10.0.0.1 after 30s while calling downstream",
			Labels:    map[string]string{"service": "payments"},
		})
	}
	handler := h.wrap(func(ctx context.Context, args map[string]any) (any, error) {
		return big, nil
	})

	result, err := handler(context.Background(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := result.Content[0].(mcp.TextContent).Text
	if len(text) > 30_000+300 {
		t.Errorf("expected shrunk result under budget, got %d bytes", len(text))
	}
	if !json.Valid([]byte(text)) {
		t.Error("shrunk result must remain valid JSON")
	}
	if stringContains(text, "TRUNCATED") {
		t.Error("known types should shrink, never byte-truncate")
	}
	if !stringContains(text, "top_patterns") {
		t.Error("analysis must survive the shrink")
	}
}
