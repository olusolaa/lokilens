// Command lokilens-http runs LokiLens as an MCP server over Streamable-HTTP.
//
// This is an alternative to cmd/lokilens-mcp (stdio) for deployments where the
// server is centrally hosted and reached by remote MCP clients over the network
// rather than spawned locally by the client. The server itself performs no
// authentication — front it with a reverse proxy (TLS + auth) in production.
//
// The bind address is read from MCP_HTTP_ADDR (default 127.0.0.1:8085).
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
	"github.com/olusolaa/lokilens/internal/lokimcp/safety"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.LoadMCP()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

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

	checkCtx, checkCancel := context.WithTimeout(ctx, 10*time.Second)
	if err := source.HealthCheck(checkCtx); err != nil {
		checkCancel()
		log.Fatalf("health check failed (%s): %v", source.Name(), err)
	}
	checkCancel()
	logger.Info("log backend connected", "backend", source.Name())

	piiFilter := safety.NewPIIFilter()
	mcpServer := mcppkg.NewServer(source, piiFilter, auditLogger, logger)

	addr := os.Getenv("MCP_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8085"
	}

	httpServer := server.NewStreamableHTTPServer(mcpServer)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("MCP server starting", "backend", source.Name(), "transport", "streamable-http", "addr", addr)
		errCh <- httpServer.Start(addr)
	}()

	select {
	case <-ctx.Done():
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		if err := httpServer.Shutdown(shutCtx); err != nil {
			log.Fatalf("shutdown: %v", err)
		}
	case err := <-errCh:
		if err != nil {
			log.Fatalf("mcp server: %v", err)
		}
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
