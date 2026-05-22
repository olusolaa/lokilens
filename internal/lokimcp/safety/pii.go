package safety

import (
	"net"
	"regexp"
)

// PIIFilter detects and redacts personally identifiable information.
type PIIFilter struct {
	patterns []piiPattern
}

type piiPattern struct {
	name    string
	re      *regexp.Regexp
	replace string
	filter  func(match string) bool // optional: return true to KEEP the match (skip redaction)
}

// privateIPNets are RFC 1918 private ranges + localhost — these are infrastructure
// addresses, not customer PII, and are essential for debugging.
var privateIPNets = func() []*net.IPNet {
	cidrs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, _ := net.ParseCIDR(cidr)
		nets = append(nets, n)
	}
	return nets
}()

// isPrivateIP returns true if the IP is in a private/internal range.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range privateIPNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// NewPIIFilter creates a PII filter with default patterns.
func NewPIIFilter() *PIIFilter {
	return &PIIFilter{
		patterns: []piiPattern{
			{
				name:    "email",
				re:      regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
				replace: "[REDACTED_EMAIL]",
			},
			{
				name:    "ssn",
				re:      regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
				replace: "[REDACTED_SSN]",
			},
			{
				name:    "credit_card",
				re:      regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
				replace: "[REDACTED_CC]",
				// Only redact 16-digit numbers that pass Luhn validation.
				// In production logs, trace IDs, transaction IDs, and Kafka keys
				// are often 16 digits — redacting them as [REDACTED_CC] makes
				// incident investigation impossible. Real credit card numbers
				// always pass Luhn; random 16-digit numbers fail ~90% of the time.
				filter: func(match string) bool { return !luhnValid(match) },
			},
			{
				// Amex cards use 15 digits in 4-6-5 grouping (e.g. 3782-822463-10005).
				// The main credit_card pattern only catches 16-digit (4-4-4-4) cards,
				// leaving Amex numbers unredacted — a compliance gap.
				name:    "credit_card_amex",
				re:      regexp.MustCompile(`\b\d{4}[- ]?\d{6}[- ]?\d{5}\b`),
				replace: "[REDACTED_CC]",
				filter:  func(match string) bool { return !luhnValid(match) },
			},
			{
				name: "ipv4",
				// Match all IPv4 addresses, but the filter preserves private/internal ranges
				// (10.x, 172.16-31.x, 192.168.x, 127.x) because they are infrastructure
				// addresses essential for debugging, not customer PII.
				re:      regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b`),
				replace: "[REDACTED_IP]",
				filter:  isPrivateIP,
			},
			{
				name:    "jwt",
				re:      regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
				replace: "[REDACTED_JWT]",
			},
			{
				name:    "bearer_token",
				re:      regexp.MustCompile(`Bearer\s+[A-Za-z0-9._~+/=\-]+`),
				replace: "Bearer [REDACTED]",
			},
		},
	}
}

// Redact replaces PII patterns in text with redaction markers.
func (f *PIIFilter) Redact(text string) string {
	for _, p := range f.patterns {
		text = replaceFiltered(text, p)
	}
	return text
}

// RedactWithCount replaces PII patterns and returns the count of distinct
// pattern types that matched. Useful for audit logging without leaking content.
func (f *PIIFilter) RedactWithCount(text string) (string, int) {
	count := 0
	for _, p := range f.patterns {
		newText := replaceFiltered(text, p)
		if newText != text {
			count++
		}
		text = newText
	}
	return text, count
}

// luhnValid checks if a numeric string (with optional dashes/spaces) passes the
// Luhn algorithm. All valid credit card numbers pass Luhn; most random 16-digit
// numbers (trace IDs, transaction IDs) do not. This reduces PII false positives
// from ~100% to ~10% in production logging environments.
func luhnValid(s string) bool {
	// Strip separators
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false // not a plausible card length
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// replaceFiltered applies a PII pattern, respecting the optional filter function.
// If filter returns true for a match, that match is preserved (not redacted).
func replaceFiltered(text string, p piiPattern) string {
	if p.filter == nil {
		return p.re.ReplaceAllString(text, p.replace)
	}
	return p.re.ReplaceAllStringFunc(text, func(match string) string {
		if p.filter(match) {
			return match // keep it
		}
		return p.replace
	})
}
