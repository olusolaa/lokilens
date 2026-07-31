package prometheus

import (
	"context"
	"fmt"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

type Source struct {
	handlers *ToolHandlers
}

func NewSource(client Client, validator *Validator, auditLogger *audit.Logger) *Source {
	return &Source{handlers: NewToolHandlers(client, validator, auditLogger)}
}

func (s *Source) Name() string        { return "Prometheus" }
func (s *Source) Instruction() string { return systemInstruction }
func (s *Source) Description() string {
	return "Metrics analysis assistant that queries Prometheus via natural language"
}
func (s *Source) Handlers() *ToolHandlers { return s.handlers }

func (s *Source) HealthCheck(ctx context.Context) error {
	_, err := s.handlers.client.Query(ctx, InstantQueryRequest{Query: "1"})
	if err != nil {
		return fmt.Errorf("prometheus unreachable: %w", err)
	}
	return nil
}

const systemInstruction = `You are querying a Prometheus metrics backend.

Workflow:
1. Call list_metrics FIRST to discover metric names (optionally filter with a selector).
2. Use get_metric_metadata to understand a metric's type/help/unit.
3. Use get_metric_label_values to find label values (e.g. instance, job, service) for selectors.
4. Use query_metrics_instant for "right now" values, query_metrics_range for trends over time.

Write valid PromQL. For rates of counters use rate(metric[5m]). Prefer narrow selectors.`
