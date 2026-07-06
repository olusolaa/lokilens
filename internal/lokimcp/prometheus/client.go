package prometheus

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

	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
)

const maxResponseBodySize = 50 << 20 // 50 MB

// Client queries a Prometheus-compatible metrics backend.
type Client interface {
	Query(ctx context.Context, req InstantQueryRequest) (*loki.QueryResponse, error)
	QueryRange(ctx context.Context, req QueryRangeRequest) (*loki.QueryResponse, error)
	Labels(ctx context.Context, req LabelsRequest) (*loki.LabelsResponse, error)
	LabelValues(ctx context.Context, req LabelValuesRequest) (*loki.LabelsResponse, error)
	Metadata(ctx context.Context, req MetadataRequest) (*MetadataResponse, error)
}

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

// formatUnix renders a time as Prometheus unix seconds.
func formatUnix(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

func (c *httpClient) Query(ctx context.Context, req InstantQueryRequest) (*loki.QueryResponse, error) {
	params := url.Values{"query": {req.Query}}
	if !req.Time.IsZero() {
		params.Set("time", formatUnix(req.Time))
	}
	var resp loki.QueryResponse
	if err := c.get(ctx, "/api/v1/query", params, &resp); err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) QueryRange(ctx context.Context, req QueryRangeRequest) (*loki.QueryResponse, error) {
	params := url.Values{
		"query": {req.Query},
		"start": {formatUnix(req.Start)},
		"end":   {formatUnix(req.End)},
		"step":  {req.Step},
	}
	var resp loki.QueryResponse
	if err := c.get(ctx, "/api/v1/query_range", params, &resp); err != nil {
		return nil, fmt.Errorf("query_range: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) Labels(ctx context.Context, req LabelsRequest) (*loki.LabelsResponse, error) {
	params := url.Values{}
	if !req.Start.IsZero() {
		params.Set("start", formatUnix(req.Start))
	}
	if !req.End.IsZero() {
		params.Set("end", formatUnix(req.End))
	}
	if req.Match != "" {
		params.Set("match[]", req.Match)
	}
	var resp loki.LabelsResponse
	if err := c.get(ctx, "/api/v1/labels", params, &resp); err != nil {
		return nil, fmt.Errorf("labels: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) LabelValues(ctx context.Context, req LabelValuesRequest) (*loki.LabelsResponse, error) {
	params := url.Values{}
	if !req.Start.IsZero() {
		params.Set("start", formatUnix(req.Start))
	}
	if !req.End.IsZero() {
		params.Set("end", formatUnix(req.End))
	}
	if req.Match != "" {
		params.Set("match[]", req.Match)
	}
	path := fmt.Sprintf("/api/v1/label/%s/values", url.PathEscape(req.LabelName))
	var resp loki.LabelsResponse
	if err := c.get(ctx, path, params, &resp); err != nil {
		return nil, fmt.Errorf("label_values(%s): %w", req.LabelName, err)
	}
	return &resp, nil
}

func (c *httpClient) Metadata(ctx context.Context, req MetadataRequest) (*MetadataResponse, error) {
	params := url.Values{}
	if req.Metric != "" {
		params.Set("metric", req.Metric)
	}
	var resp MetadataResponse
	if err := c.get(ctx, "/api/v1/metadata", params, &resp); err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) get(ctx context.Context, path string, params url.Values, out any) error {
	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	makeReq := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		if c.apiKey != "" {
			r.Header.Set("Authorization", "Bearer "+c.apiKey)
		}
		return r, nil
	}
	resp, err := c.doWithRetry(ctx, makeReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return NewPromError(resp.StatusCode, string(body), nil)
	}
	limited := io.LimitReader(resp.Body, maxResponseBodySize)
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
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
			lastErr = fmt.Errorf("prometheus returned HTTP %d: %s", resp.StatusCode, string(body))
			continue
		}
		return resp, nil
	}
	return nil, NewPromError(lastStatusCode, fmt.Sprintf("request failed after %d attempts", c.maxRetries+1), lastErr)
}
