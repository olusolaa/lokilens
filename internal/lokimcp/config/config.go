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
	}

	if cfg.LokiBaseURL == "" && cfg.PromBaseURL == "" {
		return nil, fmt.Errorf("at least one backend required: set LOKI_BASE_URL and/or PROM_BASE_URL")
	}

	return cfg, nil
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
