# LokiLens

Loki-only MCP server for Cursor, Claude Code, and other MCP-compatible clients.

## Architecture

- `cmd/lokilens-mcp`: stdio entrypoint
- `internal/lokimcp/audit`: audit logger
- `internal/lokimcp/mcp`: MCP server and tool registration
- `internal/lokimcp/loki`: Loki client, handlers, source, instruction, output shaping, and auto-widening
- `internal/lokimcp/safety`: query validation and PII filtering
- `internal/lokimcp/config`: MCP config loading

## Development

```bash
make build
make test
go build -o bin/lokilens-mcp ./cmd/lokilens-mcp
```

## MCP Usage

```json
{
  "mcpServers": {
    "lokilens": {
      "command": "/path/to/lokilens-mcp",
      "env": {
        "LOKI_BASE_URL": "http://localhost:3100"
      }
    }
  }
}
```

`LOKI_API_KEY`, `LOKI_TIMEOUT`, `LOKI_MAX_RETRIES`, `MAX_RESULTS`, and `LOG_LEVEL` are optional.

## Key Patterns

- Use the Loki package's auto-widening helpers for zero-result widening instead of duplicating range expansion.
- Keep tool outputs structured and compact.
- Run PII filtering before results leave the MCP server.
