package grafana

import (
	"context"
	"fmt"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

type Source struct {
	handlers *ToolHandlers
}

func NewSource(client Client, cfg HandlerConfig, auditLogger *audit.Logger) *Source {
	return &Source{handlers: NewToolHandlers(client, cfg, auditLogger)}
}

func (s *Source) Name() string            { return "Grafana" }
func (s *Source) Handlers() *ToolHandlers { return s.handlers }
func (s *Source) HasAthena() bool         { return s.handlers.athenaUID != "" }
func (s *Source) HasCloudWatch() bool     { return s.handlers.cloudWatchUID != "" }
func (s *Source) HasPostgres() bool       { return len(s.handlers.postgresUIDs) > 0 }

func (s *Source) Instruction() string {
	text := ""
	if s.HasAthena() {
		text += athenaInstruction
	}
	if s.HasCloudWatch() {
		text += cloudWatchInstruction
	}
	if s.HasPostgres() {
		text += postgresInstruction
	}
	return text
}

func (s *Source) HealthCheck(ctx context.Context) error {
	for _, uid := range []string{s.handlers.athenaUID, s.handlers.cloudWatchUID} {
		if uid == "" {
			continue
		}
		if _, err := s.handlers.client.DataSource(ctx, uid); err != nil {
			return fmt.Errorf("grafana datasource %s unreachable: %w", uid, err)
		}
	}
	return nil
}

const athenaInstruction = `ALB access logs (Athena via Grafana):
1. Call describe_access_logs to see tables and columns.
2. Call query_access_logs with Presto SQL. Always include $__dayFilter in WHERE; it expands to the day partitions of start_time..end_time.
   Prefer aggregates: SELECT elb_status_code, count(*) FROM user_gateway_alb_access_logs WHERE $__dayFilter GROUP BY 1
   time is an ISO-8601 string; filter finer than a day with time >= '2026-10-14T10:00:00'.
   client_ip is the Cloudflare edge, not the end user. trace_id is the ALB X-Amzn-Trace-Id.
`

const cloudWatchInstruction = `AWS CloudWatch metrics (via Grafana):
1. list_cloudwatch_metrics with a namespace (AWS/RDS, AWS/ApplicationELB, AWS/SQS, AWS/AutoScaling, AWS/ElastiCache); omit namespace to list namespaces.
2. get_cloudwatch_dimensions to find dimension keys, then values (e.g. DBInstanceIdentifier, LoadBalancer, QueueName).
3. query_cloudwatch with exact dimensions. Use "*" as a dimension value to match all.
Aurora PostgreSQL has no DMLLatency; use ReadLatency, WriteLatency, CommitLatency. Count metrics publish nothing while zero.
`

const postgresInstruction = `PostgreSQL query plans (EXPLAIN via Grafana):
1. explain_query with a database name and one SELECT, WITH or VALUES statement. It returns the plan only; the query is never executed and no rows are returned.
2. On PostgreSQL 16 databases pass $1-style placeholders (GENERIC_PLAN), e.g. the exact text from pg_stat_statements. audit and grey-db-prod run PostgreSQL 14: use literal values there.
3. Prefer reader databases (transaction reader-1, grey-db-prod-replica:*); planner statistics are shared with the writer, so plans match.
`
