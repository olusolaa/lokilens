package loki

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoWithRetry_PreservesStatusCodeAfterRetries(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	defer srv.Close()

	client := NewHTTPClient(ClientConfig{
		BaseURL:    srv.URL,
		MaxRetries: 2,
	})

	_, err := client.Labels(context.Background(), LabelsRequest{})
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}

	// Unwrap to find the LokiError
	var lokiErr *LokiError
	if !errors.As(err, &lokiErr) {
		t.Fatalf("expected *LokiError, got %T: %v", err, err)
	}

	if lokiErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status code %d, got %d", http.StatusServiceUnavailable, lokiErr.StatusCode)
	}

	// Should have attempted 3 times (1 initial + 2 retries)
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestDoWithRetry_ReturnsSuccessAfterTransientFailure(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"service unavailable"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","data":["service","level"]}`))
	}))
	defer srv.Close()

	client := NewHTTPClient(ClientConfig{
		BaseURL:    srv.URL,
		MaxRetries: 2,
	})

	resp, err := client.Labels(context.Background(), LabelsRequest{})
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}

	if len(resp.Data) != 2 {
		t.Errorf("expected 2 labels, got %d", len(resp.Data))
	}
}

func TestDoWithRetry_Preserves429StatusCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`rate limited`))
	}))
	defer srv.Close()

	client := NewHTTPClient(ClientConfig{
		BaseURL:    srv.URL,
		MaxRetries: 1,
	})

	_, err := client.Labels(context.Background(), LabelsRequest{})
	if err == nil {
		t.Fatal("expected error")
	}

	var lokiErr *LokiError
	if !errors.As(err, &lokiErr) {
		t.Fatalf("expected *LokiError, got %T: %v", err, err)
	}

	if lokiErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected status code %d, got %d", http.StatusTooManyRequests, lokiErr.StatusCode)
	}
}
