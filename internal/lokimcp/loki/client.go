package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// maxResponseBodySize limits Loki response reads to prevent OOM from oversized results.
const maxResponseBodySize = 50 << 20 // 50 MB

// Client defines the interface for querying a log backend.
type Client interface {
	QueryRange(ctx context.Context, req QueryRangeRequest) (*QueryResponse, error)
	Query(ctx context.Context, req InstantQueryRequest) (*QueryResponse, error)
	Labels(ctx context.Context, req LabelsRequest) (*LabelsResponse, error)
	LabelValues(ctx context.Context, req LabelValuesRequest) (*LabelsResponse, error)
}

// ClientConfig holds configuration for creating a Loki HTTP client.
type ClientConfig struct {
	BaseURL    string
	APIKey     string
	Timeout    time.Duration
	MaxRetries int
	Logger     *slog.Logger
}

type httpClient struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
	maxRetries int
	logger     *slog.Logger
}

// NewHTTPClient creates a new Loki HTTP client.
func NewHTTPClient(cfg ClientConfig) Client {
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
		apiKey:     cfg.APIKey,
		maxRetries: cfg.MaxRetries,
		logger:     cfg.Logger,
	}
}

func (c *httpClient) QueryRange(ctx context.Context, req QueryRangeRequest) (*QueryResponse, error) {
	params := url.Values{
		"query": {req.Query},
		"start": {FormatNano(req.Start)},
		"end":   {FormatNano(req.End)},
	}
	if req.Limit > 0 {
		params.Set("limit", strconv.Itoa(req.Limit))
	}
	if req.Direction != "" {
		params.Set("direction", req.Direction)
	}
	if req.Step != "" {
		params.Set("step", req.Step)
	}

	c.logger.Debug("executing range query",
		"query", req.Query,
		"start", req.Start.Format(time.RFC3339),
		"end", req.End.Format(time.RFC3339),
		"limit", req.Limit,
	)

	var resp QueryResponse
	if err := c.get(ctx, "/loki/api/v1/query_range", params, &resp); err != nil {
		return nil, fmt.Errorf("query_range: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) Query(ctx context.Context, req InstantQueryRequest) (*QueryResponse, error) {
	params := url.Values{
		"query": {req.Query},
	}
	if !req.Time.IsZero() {
		params.Set("time", FormatNano(req.Time))
	}
	if req.Limit > 0 {
		params.Set("limit", strconv.Itoa(req.Limit))
	}
	if req.Direction != "" {
		params.Set("direction", req.Direction)
	}

	var resp QueryResponse
	if err := c.get(ctx, "/loki/api/v1/query", params, &resp); err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) Labels(ctx context.Context, req LabelsRequest) (*LabelsResponse, error) {
	params := url.Values{}
	if !req.Start.IsZero() {
		params.Set("start", FormatNano(req.Start))
	}
	if !req.End.IsZero() {
		params.Set("end", FormatNano(req.End))
	}

	var resp LabelsResponse
	if err := c.get(ctx, "/loki/api/v1/labels", params, &resp); err != nil {
		return nil, fmt.Errorf("labels: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) LabelValues(ctx context.Context, req LabelValuesRequest) (*LabelsResponse, error) {
	params := url.Values{}
	if !req.Start.IsZero() {
		params.Set("start", FormatNano(req.Start))
	}
	if !req.End.IsZero() {
		params.Set("end", FormatNano(req.End))
	}
	if req.Query != "" {
		params.Set("query", req.Query)
	}

	path := fmt.Sprintf("/loki/api/v1/label/%s/values", url.PathEscape(req.LabelName))

	var resp LabelsResponse
	if err := c.get(ctx, path, params, &resp); err != nil {
		return nil, fmt.Errorf("label_values(%s): %w", req.LabelName, err)
	}
	return &resp, nil
}

func (c *httpClient) get(ctx context.Context, path string, params url.Values, out any) error {
	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	makeReq := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		if c.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
		}
		return req, nil
	}

	resp, err := c.doWithRetry(ctx, makeReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return NewLokiError(resp.StatusCode, string(body), nil)
	}

	// Size-limit the response to prevent OOM from oversized Loki results.
	limited := io.LimitReader(resp.Body, maxResponseBodySize)
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

// doWithRetry executes HTTP requests with exponential backoff.
// makeReq creates a fresh *http.Request for each attempt to avoid reusing consumed state.
func (c *httpClient) doWithRetry(ctx context.Context, makeReq func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	lastStatusCode := 0

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond
			c.logger.Debug("retrying request", "attempt", attempt, "backoff", backoff)
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
			lastErr = fmt.Errorf("loki returned HTTP %d: %s", resp.StatusCode, string(body))
			continue
		}

		return resp, nil
	}

	return nil, NewLokiError(lastStatusCode, fmt.Sprintf("request failed after %d attempts", c.maxRetries+1), lastErr)
}
