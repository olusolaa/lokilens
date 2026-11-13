package config

import (
	"os"
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"LOKI_BASE_URL", "PROM_BASE_URL", "PROM_MAX_POINTS"} {
		os.Unsetenv(k)
	}
}

func TestLoadMCP_RequiresAtLeastOneBackend(t *testing.T) {
	clearEnv(t)
	if _, err := LoadMCP(); err == nil {
		t.Fatal("expected error when neither LOKI_BASE_URL nor PROM_BASE_URL is set")
	}
}

func TestLoadMCP_PromOnlyIsValid(t *testing.T) {
	clearEnv(t)
	os.Setenv("PROM_BASE_URL", "http://localhost:9090")
	defer os.Unsetenv("PROM_BASE_URL")
	cfg, err := LoadMCP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PromBaseURL != "http://localhost:9090" {
		t.Fatalf("PromBaseURL = %q", cfg.PromBaseURL)
	}
	if cfg.PromMaxPoints != 11000 {
		t.Fatalf("PromMaxPoints default = %d, want 11000", cfg.PromMaxPoints)
	}
}

func TestLoadMCP_LokiOnlyStillValid(t *testing.T) {
	clearEnv(t)
	os.Setenv("LOKI_BASE_URL", "http://localhost:3100")
	defer os.Unsetenv("LOKI_BASE_URL")
	if _, err := LoadMCP(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDatasourceMap(t *testing.T) {
	got, err := parseDatasourceMap(" grey-db-prod-replica:card-db=pg-abc , grey-db-audit-prod=pg-def,")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["grey-db-prod-replica:card-db"] != "pg-abc" || got["grey-db-audit-prod"] != "pg-def" {
		t.Fatalf("got %v", got)
	}
	if empty, err := parseDatasourceMap(""); err != nil || len(empty) != 0 {
		t.Fatalf("empty: %v %v", empty, err)
	}
	if _, err := parseDatasourceMap("missing-uid"); err == nil {
		t.Fatal("expected error for entry without =")
	}
}

func TestParseZoneMap(t *testing.T) {
	got, err := parseZoneMap(" grey.engineering=e58607c2de82ee0a6495d4a4c92d981b , grey.co=ce068f01875cb464a6aface167b0510b,")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["grey.engineering"] != "e58607c2de82ee0a6495d4a4c92d981b" || got["grey.co"] != "ce068f01875cb464a6aface167b0510b" {
		t.Fatalf("got %v", got)
	}
	if empty, err := parseZoneMap(""); err != nil || len(empty) != 0 {
		t.Fatalf("empty: %v %v", empty, err)
	}
	for _, bad := range []string{"missing-tag", "=abc", "name=", "name=a b", `name=a"b`, "a=abc,a=def"} {
		if _, err := parseZoneMap(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestLoadMCP_CloudflareOnlyIsValid(t *testing.T) {
	clearEnv(t)
	os.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	os.Setenv("CLOUDFLARE_ZONES", "grey.co=ce068f01875cb464a6aface167b0510b")
	defer os.Unsetenv("CLOUDFLARE_API_TOKEN")
	defer os.Unsetenv("CLOUDFLARE_ZONES")
	cfg, err := LoadMCP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.CloudflareEnabled() || cfg.CloudflareMaxTimeRange.Hours() != 168 || cfg.CloudflareMaxRetries != 2 || cfg.CloudflareTimeout.Seconds() != 30 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestLoadMCP_CloudflareTokenWithoutZonesIsNotABackend(t *testing.T) {
	clearEnv(t)
	os.Setenv("CLOUDFLARE_API_TOKEN", "tok")
	defer os.Unsetenv("CLOUDFLARE_API_TOKEN")
	if _, err := LoadMCP(); err == nil {
		t.Fatal("expected error when only the token is set")
	}
}

func TestLoadMCP_MalformedCloudflareZones(t *testing.T) {
	clearEnv(t)
	os.Setenv("LOKI_BASE_URL", "http://localhost:3100")
	os.Setenv("CLOUDFLARE_ZONES", "broken")
	defer os.Unsetenv("LOKI_BASE_URL")
	defer os.Unsetenv("CLOUDFLARE_ZONES")
	if _, err := LoadMCP(); err == nil {
		t.Fatal("expected config error for malformed CLOUDFLARE_ZONES")
	}
}
