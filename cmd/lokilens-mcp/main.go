// Command mcp runs LokiLens as an MCP (Model Context Protocol) server over stdio.
// This allows Cursor, Claude Code, and other MCP clients to use LokiLens log
// querying tools directly — the IDE's AI orchestrates the tools instead of Gemini.
//
// Usage in Cursor (.cursor/mcp.json):
//
//	{
//	  "mcpServers": {
//	    "lokilens": {
//	      "command": "/path/to/lokilens-mcp",
//	      "env": {
//	        "LOKI_BASE_URL": "http://localhost:3100"
//	      }
//	    }
//	  }
//	}
package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/lokilens/lokilens/internal/lokimcp/audit"
	"github.com/lokilens/lokilens/internal/lokimcp/config"
	"github.com/lokilens/lokilens/internal/lokimcp/loki"
	mcppkg "github.com/lokilens/lokilens/internal/lokimcp/mcp"
	"github.com/lokilens/lokilens/internal/lokimcp/safety"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.LoadMCP()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// MCP servers communicate over stdio, so all logging goes to stderr.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	}))

	auditLogger := audit.New(logger)
	lokiClient := loki.NewHTTPClient(loki.ClientConfig{
		BaseURL:    cfg.LokiBaseURL,
		APIKey:     cfg.LokiAPIKey,
		Timeout:    cfg.LokiTimeout,
		MaxRetries: cfg.LokiMaxRetries,
		Logger:     logger,
	})
	validator := safety.NewValidator(cfg.MaxResults)
	source := loki.NewSource(lokiClient, validator, auditLogger)

	// Health check the backend.
	checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
	if err := source.HealthCheck(checkCtx); err != nil {
		checkCancel()
		log.Fatalf("health check failed (%s): %v", source.Name(), err)
	}
	checkCancel()
	logger.Info("log backend connected", "backend", source.Name())

	// Create and run the MCP server over stdio.
	piiFilter := safety.NewPIIFilter()
	mcpServer := mcppkg.NewServer(source, piiFilter, auditLogger, logger)
	stdio := server.NewStdioServer(mcpServer)
	stdio.SetErrorLogger(log.New(os.Stderr, "mcp: ", log.LstdFlags))

	logger.Info("MCP server starting", "backend", source.Name(), "transport", "stdio")

	if err := stdio.Listen(ctx, os.Stdin, os.Stdout); err != nil {
		log.Fatalf("mcp server: %v", err)
	}
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
