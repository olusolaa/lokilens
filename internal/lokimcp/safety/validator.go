package safety

import (
	"fmt"
	"regexp"
	"strings"
)

// Validator enforces safety constraints on queries.
type Validator struct {
	maxResults int
}

// NewValidator creates a new query validator.
func NewValidator(maxResults int) *Validator {
	return &Validator{
		maxResults: maxResults,
	}
}

var (
	labelMatcherPattern = regexp.MustCompile(`\{[^}]*\w+\s*[=!~]+\s*"[^"]*"`)
	dangerousRegex      = regexp.MustCompile(`\|~\s*"\.[\*\+]"`)
)

// SanitizeQuery auto-fixes common model mistakes in LogQL queries.
// Returns the fixed query. Call this before ValidateQuery.
func SanitizeQuery(logql string) string {
	// Auto-fix empty stream selector: {} → {service_name=~".+"}
	// The model sometimes forgets to include a stream selector when
	// translating from other query formats. The intent is always
	// "search all services" so we fix it instead of erroring.
	if strings.Contains(logql, "{}") {
		logql = strings.Replace(logql, "{}", `{service_name=~".+"}`, 1)
	}
	return logql
}

// ValidateQuery checks that a LogQL query is safe to execute.
func (v *Validator) ValidateQuery(logql, startTime, endTime string) error {
	if strings.TrimSpace(logql) == "" {
		return fmt.Errorf("query cannot be empty")
	}

	// Require at least one label matcher
	if !labelMatcherPattern.MatchString(logql) {
		return fmt.Errorf("query must include at least one label matcher (e.g., {service=\"myapp\"})")
	}

	// Reject dangerous regex patterns
	if dangerousRegex.MatchString(logql) {
		return fmt.Errorf("query contains potentially expensive regex pattern — be more specific")
	}

	return nil
}

// MaxResults returns the configured maximum result limit.
func (v *Validator) MaxResults() int {
	return v.maxResults
}
