package tempo

import (
	"context"
	"fmt"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

type Source struct {
	handlers *ToolHandlers
}

func NewSource(client Client, maxRange time.Duration, auditLogger *audit.Logger) *Source {
	return &Source{handlers: NewToolHandlers(client, maxRange, auditLogger)}
}

func (s *Source) Name() string        { return "Tempo" }
func (s *Source) Instruction() string { return systemInstruction }
func (s *Source) Description() string {
	return "Trace analysis assistant that queries Grafana Tempo with TraceQL"
}
func (s *Source) Handlers() *ToolHandlers { return s.handlers }

func (s *Source) HealthCheck(ctx context.Context) error {
	if err := s.handlers.client.Echo(ctx); err != nil {
		return fmt.Errorf("tempo unreachable: %w", err)
	}
	return nil
}

const systemInstruction = `You are querying a Grafana Tempo trace backend with TraceQL.

Workflow:
1. Use get_trace_tag_values with tag "resource.service.name" to see which services emit traces.
2. Use get_trace_tags to discover span/resource attributes you can filter on.
3. Use search_traces with TraceQL to find candidate traces, e.g.
   {resource.service.name="wallet-service" && kind=server && duration>1s}
   {status=error && resource.service.name="user-gateway"}
   {span.http.response.status_code>=500}
4. Use get_trace on a trace_id to see the span tree: services, errors, and where time went.
   Narrow large traces with service or min_duration_ms.

Trace IDs found in logs (trace_id field) can be passed straight to get_trace.
Keep time ranges narrow; search scans storage and is slower over wide ranges.`
