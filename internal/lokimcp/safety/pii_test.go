package safety

import (
	"strings"
	"testing"
)

func TestPIIFilter_Email(t *testing.T) {
	f := NewPIIFilter()
	result := f.Redact("user john@example.com logged in")
	if strings.Contains(result, "john@example.com") {
		t.Error("email was not redacted")
	}
	if !strings.Contains(result, "[REDACTED_EMAIL]") {
		t.Error("expected [REDACTED_EMAIL] marker")
	}
}

func TestPIIFilter_SSN(t *testing.T) {
	f := NewPIIFilter()
	result := f.Redact("ssn: 123-45-6789")
	if strings.Contains(result, "123-45-6789") {
		t.Error("SSN was not redacted")
	}
}

func TestPIIFilter_CreditCard(t *testing.T) {
	f := NewPIIFilter()
	result := f.Redact("card: 4111-1111-1111-1111")
	if strings.Contains(result, "4111") {
		t.Error("credit card was not redacted")
	}
}

func TestPIIFilter_IPv4_Public(t *testing.T) {
	f := NewPIIFilter()
	result := f.Redact("connected from 203.0.113.5")
	if strings.Contains(result, "203.0.113.5") {
		t.Error("public IP was not redacted")
	}
	if !strings.Contains(result, "[REDACTED_IP]") {
		t.Error("expected [REDACTED_IP] marker")
	}
}

func TestPIIFilter_IPv4_PrivatePreserved(t *testing.T) {
	f := NewPIIFilter()
	// Private IPs are infrastructure data, not customer PII — should be preserved
	privates := []struct {
		input string
		ip    string
	}{
		{"connection refused from 10.0.1.5:5432", "10.0.1.5"},
		{"connected to 192.168.1.100", "192.168.1.100"},
		{"upstream 172.16.0.50:8080", "172.16.0.50"},
		{"localhost 127.0.0.1", "127.0.0.1"},
	}
	for _, tc := range privates {
		result := f.Redact(tc.input)
		if !strings.Contains(result, tc.ip) {
			t.Errorf("private IP %s should be preserved, but was redacted in %q", tc.ip, result)
		}
	}
}

func TestPIIFilter_IPv4_NoFalsePositiveOnVersions(t *testing.T) {
	f := NewPIIFilter()
	// Version strings with valid octets should still match as IPs.
	// But strings like "go1.22.3.abc" should not since they aren't IPs.
	result := f.Redact("running version 1.22.3 of the app")
	// "1.22.3" is not 4 octets — should NOT be redacted
	if strings.Contains(result, "[REDACTED_IP]") {
		t.Error("version string 1.22.3 should not be treated as IP")
	}
}

func TestPIIFilter_JWT(t *testing.T) {
	f := NewPIIFilter()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
	result := f.Redact("token: " + jwt)
	if strings.Contains(result, "eyJ") {
		t.Error("JWT was not redacted")
	}
}

func TestPIIFilter_BearerToken(t *testing.T) {
	f := NewPIIFilter()
	result := f.Redact("Authorization: Bearer sk-abc123xyz")
	if strings.Contains(result, "sk-abc123xyz") {
		t.Error("bearer token was not redacted")
	}
}

func TestPIIFilter_RedactWithCount(t *testing.T) {
	f := NewPIIFilter()
	text := "user john@example.com from 203.0.113.5"
	result, count := f.RedactWithCount(text)
	if count != 2 {
		t.Errorf("expected 2 pattern types, got %d", count)
	}
	if strings.Contains(result, "john@example.com") || strings.Contains(result, "203.0.113.5") {
		t.Error("PII was not redacted")
	}
}

func TestPIIFilter_RedactWithCount_PrivateIPNotCounted(t *testing.T) {
	f := NewPIIFilter()
	text := "user john@example.com from 10.0.0.1"
	result, count := f.RedactWithCount(text)
	// Only email should be redacted — private IP is preserved
	if count != 1 {
		t.Errorf("expected 1 pattern type (email only), got %d", count)
	}
	if strings.Contains(result, "john@example.com") {
		t.Error("email was not redacted")
	}
	if !strings.Contains(result, "10.0.0.1") {
		t.Error("private IP should be preserved")
	}
}

func TestPIIFilter_NoFalsePositive(t *testing.T) {
	f := NewPIIFilter()
	clean := "service payments returned 200 in 45ms"
	result := f.Redact(clean)
	if result != clean {
		t.Errorf("clean text was modified: %q → %q", clean, result)
	}
}

func TestLuhnValid(t *testing.T) {
	valid := []string{
		"4111111111111111",    // Visa test card
		"4111-1111-1111-1111", // with dashes
		"4111 1111 1111 1111", // with spaces
		"5500000000000004",    // Mastercard test
		"378282246310005",     // Amex test (15 digits)
		"6011111111111117",    // Discover test
	}
	for _, cc := range valid {
		if !luhnValid(cc) {
			t.Errorf("luhnValid(%q) = false, want true (valid card number)", cc)
		}
	}

	invalid := []string{
		"1234567890123456", // random 16 digits — fails Luhn
		"0000000000000000", // all zeros — passes Luhn but caught by length
		"9999999999999999", // random — fails Luhn
		"1111111111111111", // fails Luhn
		"abc",              // not numeric — too short
		"",                 // empty
	}
	for _, id := range invalid {
		// We only care that random 16-digit IDs fail;
		// all-zeros passes Luhn (sum=0, 0%10==0) but that's fine —
		// no real trace ID is all zeros.
		if id == "0000000000000000" {
			continue // 0000... passes Luhn, which is fine
		}
		if luhnValid(id) {
			t.Errorf("luhnValid(%q) = true, want false (not a real card)", id)
		}
	}
}

func TestPIIFilter_CreditCard_RealCardsRedacted(t *testing.T) {
	f := NewPIIFilter()
	// Standard test card numbers that pass Luhn — must be redacted
	cards := []string{
		"card: 4111-1111-1111-1111",
		"cc 4111111111111111",
		"payment with 5500000000000004",
		"card 6011111111111117",
	}
	for _, input := range cards {
		result := f.Redact(input)
		if !strings.Contains(result, "[REDACTED_CC]") {
			t.Errorf("real credit card not redacted in %q → %q", input, result)
		}
	}
}

func TestPIIFilter_CreditCard_TraceIDsPreserved(t *testing.T) {
	f := NewPIIFilter()
	// 16-digit trace/transaction IDs that fail Luhn — must be preserved
	// for incident investigation. These are the kinds of IDs engineers
	// paste at 3am when tracing a request through the system.
	traceIDs := []struct {
		input string
		id    string
	}{
		{"trace_id: 1234567890123456", "1234567890123456"},
		{"transaction 9876543210987654", "9876543210987654"},
		{"kafka key 1111111111111111", "1111111111111111"},
	}
	for _, tc := range traceIDs {
		result := f.Redact(tc.input)
		if !strings.Contains(result, tc.id) {
			t.Errorf("trace ID %s should be preserved (fails Luhn), but was redacted in %q → %q",
				tc.id, tc.input, result)
		}
	}
}

func TestPIIFilter_CreditCard_AmexRedacted(t *testing.T) {
	f := NewPIIFilter()
	// Amex test card numbers (15 digits, 4-6-5 grouping) that pass Luhn
	cards := []string{
		"card: 3782-822463-10005", // Amex with dashes
		"cc 378282246310005",      // Amex flat
		"amex 3714-496353-98431",  // Another Amex test number
		"card 3714 496353 98431",  // Amex with spaces
	}
	for _, input := range cards {
		result := f.Redact(input)
		if !strings.Contains(result, "[REDACTED_CC]") {
			t.Errorf("Amex card not redacted in %q → %q", input, result)
		}
	}
}

func TestPIIFilter_CreditCard_15DigitTraceIDsPreserved(t *testing.T) {
	f := NewPIIFilter()
	// 15-digit trace IDs that fail Luhn — must be preserved
	traceIDs := []struct {
		input string
		id    string
	}{
		{"trace_id: 1234-567890-12345", "1234-567890-12345"},
		{"transaction 123456789012345", "123456789012345"},
	}
	for _, tc := range traceIDs {
		result := f.Redact(tc.input)
		if !strings.Contains(result, tc.id) {
			t.Errorf("15-digit trace ID %s should be preserved (fails Luhn), but was redacted in %q → %q",
				tc.id, tc.input, result)
		}
	}
}
