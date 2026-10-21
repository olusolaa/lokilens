package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	LokiBaseURL    string
	LokiAPIKey     string
	LokiTimeout    time.Duration
	LokiMaxRetries int
	MaxTimeRange   time.Duration
	MaxResults     int
	LogLevel       string

	// Prometheus metrics backend (optional). When PromBaseURL is set the
	// metric tools are registered.
	PromBaseURL    string
	PromAPIKey     string
	PromTimeout    time.Duration
	PromMaxRetries int
	PromMaxPoints  int

	TempoBaseURL    string
	TempoAPIKey     string
	TempoTimeout    time.Duration
	TempoMaxRetries int

	GrafanaURL                 string
	GrafanaToken               string
	GrafanaTimeout             time.Duration
	GrafanaMaxRetries          int
	GrafanaAthenaUID           string
	GrafanaCloudWatchUID       string
	AthenaMaxTimeRange         time.Duration
	CloudWatchMaxTimeRange     time.Duration
	CloudWatchMaxPoints        int
	GrafanaPostgresDatasources map[string]string
}

// LoadMCP loads config for the Loki-only MCP server.
func LoadMCP() (*Config, error) {
	loadDotEnv()

	cfg := &Config{
		LokiBaseURL:    os.Getenv("LOKI_BASE_URL"),
		LokiAPIKey:     os.Getenv("LOKI_API_KEY"),
		LokiTimeout:    envDuration("LOKI_TIMEOUT", 30*time.Second),
		LokiMaxRetries: envInt("LOKI_MAX_RETRIES", 2),
		MaxTimeRange:   envDuration("MAX_TIME_RANGE", 24*time.Hour),
		MaxResults:     envInt("MAX_RESULTS", 500),
		LogLevel:       envOrDefault("LOG_LEVEL", "info"),

		PromBaseURL:    os.Getenv("PROM_BASE_URL"),
		PromAPIKey:     os.Getenv("PROM_API_KEY"),
		PromTimeout:    envDuration("PROM_TIMEOUT", 30*time.Second),
		PromMaxRetries: envInt("PROM_MAX_RETRIES", 2),
		PromMaxPoints:  envInt("PROM_MAX_POINTS", 11000),

		TempoBaseURL:    os.Getenv("TEMPO_BASE_URL"),
		TempoAPIKey:     os.Getenv("TEMPO_API_KEY"),
		TempoTimeout:    envDuration("TEMPO_TIMEOUT", 60*time.Second),
		TempoMaxRetries: envInt("TEMPO_MAX_RETRIES", 2),

		GrafanaURL:             strings.TrimRight(os.Getenv("GRAFANA_URL"), "/"),
		GrafanaToken:           os.Getenv("GRAFANA_TOKEN"),
		GrafanaTimeout:         envDuration("GRAFANA_TIMEOUT", 120*time.Second),
		GrafanaMaxRetries:      envInt("GRAFANA_MAX_RETRIES", 2),
		GrafanaAthenaUID:       os.Getenv("GRAFANA_ATHENA_UID"),
		GrafanaCloudWatchUID:   os.Getenv("GRAFANA_CLOUDWATCH_UID"),
		AthenaMaxTimeRange:     envDuration("ATHENA_MAX_TIME_RANGE", 7*24*time.Hour),
		CloudWatchMaxTimeRange: envDuration("CLOUDWATCH_MAX_TIME_RANGE", 7*24*time.Hour),
		CloudWatchMaxPoints:    envInt("CLOUDWATCH_MAX_POINTS", 1440),
	}

	if cfg.GrafanaToken == "" {
		if path := os.Getenv("GRAFANA_TOKEN_FILE"); path != "" {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("reading GRAFANA_TOKEN_FILE: %w", err)
			}
			cfg.GrafanaToken = strings.TrimSpace(string(data))
		}
	}

	datasources, err := parseDatasourceMap(os.Getenv("GRAFANA_POSTGRES_DATASOURCES"))
	if err != nil {
		return nil, fmt.Errorf("GRAFANA_POSTGRES_DATASOURCES: %w", err)
	}
	cfg.GrafanaPostgresDatasources = datasources

	if cfg.LokiBaseURL == "" && cfg.PromBaseURL == "" && cfg.TempoBaseURL == "" && !cfg.GrafanaEnabled() {
		return nil, fmt.Errorf("at least one backend required: set LOKI_BASE_URL, PROM_BASE_URL, TEMPO_BASE_URL and/or GRAFANA_URL with a datasource UID")
	}

	return cfg, nil
}

func (c *Config) GrafanaEnabled() bool {
	return c.GrafanaURL != "" && (c.GrafanaAthenaUID != "" || c.GrafanaCloudWatchUID != "" || len(c.GrafanaPostgresDatasources) > 0)
}

func parseDatasourceMap(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, uid, ok := strings.Cut(entry, "=")
		name, uid = strings.TrimSpace(name), strings.TrimSpace(uid)
		if !ok || name == "" || uid == "" {
			return nil, fmt.Errorf("entry %q must be name=uid", entry)
		}
		out[name] = uid
	}
	return out, nil
}

func loadDotEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envDuration(key string, defaultVal time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultVal
}

func envInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}
