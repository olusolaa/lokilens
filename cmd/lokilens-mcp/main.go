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

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/config"
	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
	mcppkg "github.com/olusolaa/lokilens/internal/lokimcp/mcp"
	"github.com/olusolaa/lokilens/internal/lokimcp/prometheus"
	"github.com/olusolaa/lokilens/internal/lokimcp/safety"
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

	var logSource *loki.Source
	if cfg.LokiBaseURL != "" {
		lokiClient := loki.NewHTTPClient(loki.ClientConfig{
			BaseURL:    cfg.LokiBaseURL,
			APIKey:     cfg.LokiAPIKey,
			Timeout:    cfg.LokiTimeout,
			MaxRetries: cfg.LokiMaxRetries,
			Logger:     logger,
		})
		logSource = loki.NewSource(lokiClient, safety.NewValidator(cfg.MaxResults), auditLogger)
	}

	var metricSource *prometheus.Source
	if cfg.PromBaseURL != "" {
		promClient := prometheus.NewHTTPClient(prometheus.ClientConfig{
			BaseURL:    cfg.PromBaseURL,
			APIKey:     cfg.PromAPIKey,
			Timeout:    cfg.PromTimeout,
			MaxRetries: cfg.PromMaxRetries,
			Logger:     logger,
		})
		metricSource = prometheus.NewSource(promClient, prometheus.NewValidator(cfg.PromMaxPoints, cfg.MaxTimeRange), auditLogger)
	}

	// Health-check each configured backend. Warn (don't fatal) if one is down,
	// as long as at least one is healthy.
	healthy := 0
	checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
	if logSource != nil {
		if err := logSource.HealthCheck(checkCtx); err != nil {
			logger.Warn("log backend health check failed", "backend", logSource.Name(), "error", err)
		} else {
			healthy++
			logger.Info("log backend connected", "backend", logSource.Name())
		}
	}
	if metricSource != nil {
		if err := metricSource.HealthCheck(checkCtx); err != nil {
			logger.Warn("metric backend health check failed", "backend", metricSource.Name(), "error", err)
		} else {
			healthy++
			logger.Info("metric backend connected", "backend", metricSource.Name())
		}
	}
	checkCancel()
	if healthy == 0 {
		log.Fatalf("no backend is reachable; aborting")
	}

	// Create and run the MCP server over stdio.
	piiFilter := safety.NewPIIFilter()
	mcpServer := mcppkg.NewServer(logSource, piiFilter, auditLogger, logger, mcppkg.WithMetrics(metricSource))
	stdio := server.NewStdioServer(mcpServer)
	stdio.SetErrorLogger(log.New(os.Stderr, "mcp: ", log.LstdFlags))

	logger.Info("MCP server starting", "transport", "stdio")

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
