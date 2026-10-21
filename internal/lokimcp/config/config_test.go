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
