package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
)

type Source struct {
	handlers *ToolHandlers
}

func NewSource(client Client, zones map[string]string, maxRange time.Duration, auditLogger *audit.Logger) *Source {
	return &Source{handlers: NewToolHandlers(client, zones, maxRange, auditLogger)}
}

func (s *Source) Name() string        { return "Cloudflare" }
func (s *Source) Instruction() string { return systemInstruction }
func (s *Source) Description() string {
	return "Edge traffic and WAF analysis that queries the Cloudflare GraphQL Analytics API"
}
func (s *Source) Handlers() *ToolHandlers { return s.handlers }

func (s *Source) HealthCheck(ctx context.Context) error {
	tags := make([]string, 0, len(s.handlers.zones))
	for _, tag := range s.handlers.zones {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	quoted := make([]string, len(tags))
	for i, t := range tags {
		quoted[i] = `"` + t + `"`
	}
	q := fmt.Sprintf("{ viewer { zones(filter: {zoneTag_in: [%s]}) { zoneTag } } }", strings.Join(quoted, ", "))
	resp, err := s.handlers.client.Query(ctx, q)
	if err != nil {
		return fmt.Errorf("cloudflare unreachable: %w", err)
	}
	var data zonesData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return fmt.Errorf("decoding cloudflare zones: %w", err)
	}
	seen := map[string]bool{}
	for _, z := range data.Viewer.Zones {
		var tag string
		if raw, ok := z["zoneTag"]; ok {
			_ = json.Unmarshal(raw, &tag)
		}
		seen[tag] = true
	}
	var missing []string
	for name, tag := range s.handlers.zones {
		if !seen[tag] {
			missing = append(missing, fmt.Sprintf("%s (%s)", name, tag))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("cloudflare zones not visible to token: %s", strings.Join(missing, ", "))
	}
	return nil
}

const systemInstruction = `You are querying the Cloudflare GraphQL Analytics API through query_cloudflare.

Datasets:
- httpRequestsAdaptive: sampled individual HTTP requests at the edge.
- httpRequestsAdaptiveGroups: aggregates (count, sums, averages) grouped by dimensions.
- firewallEventsAdaptive: individual WAF and security events.

Parameters: zone (configured zone name), dataset, start/end, fields (GraphQL selection set placed inside the dataset node), filter (JSON object turned into a GraphQL filter), order_by, limit.
Counts in adaptive datasets are sampled. In httpRequestsAdaptiveGroups, include avg { sampleInterval } to see the sampling rate; raw datasets have no sampleInterval field.

Examples:
1. Status breakdown by path:
   zone="grey.engineering" dataset="httpRequestsAdaptiveGroups" fields="count dimensions { edgeResponseStatus clientRequestPath }" limit=50
2. 5xx origin errors:
   dataset="httpRequestsAdaptiveGroups" fields="count dimensions { originResponseStatus clientRequestPath }" filter={"originResponseStatus_geq":500}
3. WAF blocks with rule and client IP (raw events, no count/dimensions):
   dataset="firewallEventsAdaptive" fields="datetime action source ruleId clientIP clientCountryName clientRequestHTTPHost clientRequestPath rayName" filter={"action":"block"}
4. Trace one request by rayName:
   dataset="httpRequestsAdaptive" fields="datetime rayName clientIP clientRequestPath edgeResponseStatus" filter={"rayName":"<ray id>"}

Filter keys use the dataset's own filter field names with operator suffixes such as _geq, _leq, _in, _like, and AND/OR take arrays of objects. httpRequestsAdaptive and firewallEventsAdaptive return raw rows: select fields directly, no count/avg/dimensions. If Cloudflare rejects a field, read its error message and adjust.
To look at a specific hostname, filter by clientRequestHTTPHost.
Keep time windows narrow; wide windows are sampled more coarsely and return less precise rows.`
