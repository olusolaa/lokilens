package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	maxResponseBodySize = 50 << 20
	DefaultBaseURL      = "https://api.cloudflare.com/client/v4/graphql"
)

type Client interface {
	Query(ctx context.Context, query string) (*Response, error)
}

type ClientConfig struct {
	BaseURL    string
	APIToken   string
	Timeout    time.Duration
	MaxRetries int
	Logger     *slog.Logger
}

type httpClient struct {
	baseURL    string
	httpClient *http.Client
	apiToken   string
	maxRetries int
	logger     *slog.Logger
}

func NewHTTPClient(cfg ClientConfig) Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 2
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &httpClient{
		baseURL: cfg.BaseURL,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		apiToken:   cfg.APIToken,
		maxRetries: cfg.MaxRetries,
		logger:     cfg.Logger,
	}
}

func (c *httpClient) Query(ctx context.Context, query string) (*Response, error) {
	payload, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, fmt.Errorf("encoding query: %w", err)
	}
	makeReq := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Content-Type", "application/json")
		if c.apiToken != "" {
			r.Header.Set("Authorization", "Bearer "+c.apiToken)
		}
		return r, nil
	}
	resp, err := c.doWithRetry(ctx, makeReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, NewCloudflareError(resp.StatusCode, string(body), nil)
	}
	var out Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodySize)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	if len(out.Errors) > 0 {
		msgs := make([]string, 0, len(out.Errors))
		for _, e := range out.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, NewCloudflareError(resp.StatusCode, "graphql errors: "+strings.Join(msgs, "; "), nil)
	}
	return &out, nil
}

func (c *httpClient) doWithRetry(ctx context.Context, makeReq func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	lastStatusCode := 0
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
		req, err := makeReq()
		if err != nil {
			return nil, err
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			lastStatusCode = resp.StatusCode
			lastErr = fmt.Errorf("cloudflare returned HTTP %d: %s", resp.StatusCode, string(body))
			continue
		}
		return resp, nil
	}
	return nil, NewCloudflareError(lastStatusCode, fmt.Sprintf("request failed after %d attempts", c.maxRetries+1), lastErr)
}
