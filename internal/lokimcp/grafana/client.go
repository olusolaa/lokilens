package grafana

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const maxResponseBodySize = 50 << 20

type Client interface {
	Query(ctx context.Context, req QueryRequest) (*QueryResponse, error)
	Resource(ctx context.Context, uid, path string, params url.Values, out any) error
	DataSource(ctx context.Context, uid string) (*DataSource, error)
}

type ClientConfig struct {
	BaseURL    string
	Token      string
	Timeout    time.Duration
	MaxRetries int
	Logger     *slog.Logger
}

type httpClient struct {
	baseURL    string
	httpClient *http.Client
	token      string
	maxRetries int
	logger     *slog.Logger
}

func NewHTTPClient(cfg ClientConfig) Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
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
		token:      cfg.Token,
		maxRetries: cfg.MaxRetries,
		logger:     cfg.Logger,
	}
}

func (c *httpClient) Query(ctx context.Context, req QueryRequest) (*QueryResponse, error) {
	body, err := json.Marshal(map[string]any{
		"from":    strconv.FormatInt(req.From.UnixMilli(), 10),
		"to":      strconv.FormatInt(req.To.UnixMilli(), 10),
		"queries": req.Queries,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding query: %w", err)
	}
	resp, err := c.send(ctx, http.MethodPost, "/api/ds/query", nil, body, 0)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	var out QueryResponse
	if jerr := json.Unmarshal(raw, &out); jerr == nil && len(out.Results) > 0 {
		return &out, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, NewGrafanaError(resp.StatusCode, truncate(string(raw), 600), nil)
	}
	return nil, fmt.Errorf("decoding query response: unexpected body %q", truncate(string(raw), 200))
}

func (c *httpClient) Resource(ctx context.Context, uid, path string, params url.Values, out any) error {
	return c.getJSON(ctx, "/api/datasources/uid/"+url.PathEscape(uid)+"/resources/"+path, params, out)
}

func (c *httpClient) DataSource(ctx context.Context, uid string) (*DataSource, error) {
	var ds DataSource
	if err := c.getJSON(ctx, "/api/datasources/uid/"+url.PathEscape(uid), nil, &ds); err != nil {
		return nil, err
	}
	return &ds, nil
}

func (c *httpClient) getJSON(ctx context.Context, path string, params url.Values, out any) error {
	resp, err := c.send(ctx, http.MethodGet, path, params, nil, c.maxRetries)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return NewGrafanaError(resp.StatusCode, string(body), nil)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodySize)).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func (c *httpClient) send(ctx context.Context, method, path string, params url.Values, body []byte, retries int) (*http.Response, error) {
	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	var lastErr error
	lastStatus := 0
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if retries > 0 && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < retries {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			lastStatus = resp.StatusCode
			lastErr = fmt.Errorf("grafana returned HTTP %d: %s", resp.StatusCode, string(b))
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no attempts made")
	}
	return nil, NewGrafanaError(lastStatus, fmt.Sprintf("request failed after %d attempts", retries+1), lastErr)
}
