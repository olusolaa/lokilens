package tempo

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

const maxResponseBodySize = 50 << 20

type Client interface {
	Search(ctx context.Context, req SearchRequest) (*SearchResponse, error)
	Trace(ctx context.Context, req TraceRequest) (*TraceResponse, error)
	Tags(ctx context.Context, req TagsRequest) (*TagsResponse, error)
	TagValues(ctx context.Context, req TagValuesRequest) (*TagValuesResponse, error)
	Echo(ctx context.Context) error
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

func setRange(params url.Values, start, end time.Time) {
	if !start.IsZero() {
		params.Set("start", strconv.FormatInt(start.Unix(), 10))
	}
	if !end.IsZero() {
		params.Set("end", strconv.FormatInt(end.Unix(), 10))
	}
}

func (c *httpClient) Search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	params := url.Values{"q": {req.Query}}
	setRange(params, req.Start, req.End)
	if req.Limit > 0 {
		params.Set("limit", strconv.Itoa(req.Limit))
	}
	if req.SpansPerSpanSet > 0 {
		params.Set("spss", strconv.Itoa(req.SpansPerSpanSet))
	}
	var resp SearchResponse
	if err := c.get(ctx, "/api/search", params, &resp); err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) Trace(ctx context.Context, req TraceRequest) (*TraceResponse, error) {
	params := url.Values{}
	setRange(params, req.Start, req.End)
	var resp TraceResponse
	if err := c.get(ctx, "/api/v2/traces/"+url.PathEscape(req.TraceID), params, &resp); err != nil {
		return nil, fmt.Errorf("trace(%s): %w", req.TraceID, err)
	}
	return &resp, nil
}

func (c *httpClient) Tags(ctx context.Context, req TagsRequest) (*TagsResponse, error) {
	params := url.Values{}
	if req.Scope != "" {
		params.Set("scope", req.Scope)
	}
	setRange(params, req.Start, req.End)
	var resp TagsResponse
	if err := c.get(ctx, "/api/v2/search/tags", params, &resp); err != nil {
		return nil, fmt.Errorf("tags: %w", err)
	}
	return &resp, nil
}

func (c *httpClient) TagValues(ctx context.Context, req TagValuesRequest) (*TagValuesResponse, error) {
	params := url.Values{}
	if req.Query != "" {
		params.Set("q", req.Query)
	}
	setRange(params, req.Start, req.End)
	var resp TagValuesResponse
	path := fmt.Sprintf("/api/v2/search/tag/%s/values", url.PathEscape(req.Tag))
	if err := c.get(ctx, path, params, &resp); err != nil {
		return nil, fmt.Errorf("tag_values(%s): %w", req.Tag, err)
	}
	return &resp, nil
}

func (c *httpClient) Echo(ctx context.Context) error {
	resp, err := c.do(ctx, "/api/echo", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *httpClient) get(ctx context.Context, path string, params url.Values, out any) error {
	resp, err := c.do(ctx, path, params)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodySize)).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func (c *httpClient) do(ctx context.Context, path string, params url.Values) (*http.Response, error) {
	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	makeReq := func() (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		r.Header.Set("Accept", "application/json")
		if c.apiKey != "" {
			r.Header.Set("Authorization", "Bearer "+c.apiKey)
		}
		return r, nil
	}
	resp, err := c.doWithRetry(ctx, makeReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, NewTempoError(resp.StatusCode, string(body), nil)
	}
	return resp, nil
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
			lastErr = fmt.Errorf("tempo returned HTTP %d: %s", resp.StatusCode, string(body))
			continue
		}
		return resp, nil
	}
	return nil, NewTempoError(lastStatusCode, fmt.Sprintf("request failed after %d attempts", c.maxRetries+1), lastErr)
}
