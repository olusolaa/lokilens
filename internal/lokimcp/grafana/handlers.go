package grafana

import (
	"sync"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

type HandlerConfig struct {
	AthenaUID           string
	CloudWatchUID       string
	AthenaMaxRange      time.Duration
	CloudWatchMaxRange  time.Duration
	CloudWatchMaxPoints int
}

type ToolHandlers struct {
	client              Client
	audit               *audit.Logger
	athenaUID           string
	cloudWatchUID       string
	athenaMaxRange      time.Duration
	cloudWatchMaxRange  time.Duration
	cloudWatchMaxPoints int

	mu       sync.Mutex
	athenaDB string
}

func NewToolHandlers(client Client, cfg HandlerConfig, auditLogger *audit.Logger) *ToolHandlers {
	if cfg.AthenaMaxRange <= 0 {
		cfg.AthenaMaxRange = 7 * 24 * time.Hour
	}
	if cfg.CloudWatchMaxRange <= 0 {
		cfg.CloudWatchMaxRange = 7 * 24 * time.Hour
	}
	if cfg.CloudWatchMaxPoints <= 0 {
		cfg.CloudWatchMaxPoints = 1440
	}
	return &ToolHandlers{
		client:              client,
		audit:               auditLogger,
		athenaUID:           cfg.AthenaUID,
		cloudWatchUID:       cfg.CloudWatchUID,
		athenaMaxRange:      cfg.AthenaMaxRange,
		cloudWatchMaxRange:  cfg.CloudWatchMaxRange,
		cloudWatchMaxPoints: cfg.CloudWatchMaxPoints,
	}
}

func (h *ToolHandlers) fail(tool string, start time.Time, err error) error {
	h.audit.ToolFailed(tool, time.Since(start).Milliseconds(), err)
	return err
}
