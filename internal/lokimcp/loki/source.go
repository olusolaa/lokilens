package loki

import (
	"context"
	"fmt"

	"github.com/lokilens/lokilens/internal/lokimcp/audit"
	"github.com/lokilens/lokilens/internal/lokimcp/safety"
)

type Source struct {
	handlers *ToolHandlers
}

func NewSource(lokiClient Client, validator *safety.Validator, auditLogger *audit.Logger) *Source {
	return &Source{
		handlers: NewToolHandlers(lokiClient, validator, auditLogger),
	}
}

func (s *Source) Name() string        { return "Loki" }
func (s *Source) Instruction() string { return systemInstruction }
func (s *Source) Description() string {
	return "Log analysis assistant that queries Grafana Loki via natural language"
}

func (s *Source) Handlers() *ToolHandlers { return s.handlers }

func (s *Source) HealthCheck(ctx context.Context) error {
	_, err := s.handlers.lokiClient.Labels(ctx, LabelsRequest{})
	if err != nil {
		return fmt.Errorf("loki unreachable: %w", err)
	}
	return nil
}
