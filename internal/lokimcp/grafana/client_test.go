package grafana

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestClient_Query_SendsBodyAndToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ds/query" || r.Method != http.MethodPost {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		if body["from"] != "1700000000000" {
			t.Errorf("from = %v", body["from"])
		}
		w.Write([]byte(`{"results":{"A":{"status":200,"frames":[{"schema":{"fields":[{"name":"n","type":"number"}]},"data":{"values":[[1,2]]}}]}}}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL, Token: "tok"})
	resp, err := c.Query(context.Background(), QueryRequest{From: time.UnixMilli(1700000000000), To: time.UnixMilli(1700000060000), Queries: []map[string]any{{"refId": "A"}}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	res, err := resp.Single("A")
	if err != nil || res.Frames[0].RowCount() != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestClient_Query_SurfacesErrorIn400Body(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"results":{"A":{"status":400,"error":"COLUMN_NOT_FOUND: nope"}}}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	resp, err := c.Query(context.Background(), QueryRequest{Queries: []map[string]any{{"refId": "A"}}})
	if err != nil {
		t.Fatalf("transport err: %v", err)
	}
	if _, err := resp.Single("A"); err == nil || !strings.Contains(err.Error(), "COLUMN_NOT_FOUND") {
		t.Fatalf("err = %v", err)
	}
	if calls != 1 {
		t.Fatalf("query must not be retried, calls = %d", calls)
	}
}

func TestClient_Query_DoesNotRetry5xx(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	if _, err := c.Query(context.Background(), QueryRequest{}); err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestClient_Resource_RetriesAndDecodes(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path != "/api/datasources/uid/cw/resources/dimension-keys" || r.URL.Query().Get("namespace") != "AWS/RDS" {
			t.Errorf("got %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		w.Write([]byte(`[{"value":"DBInstanceIdentifier"}]`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	var items []valueItem
	if err := c.Resource(context.Background(), "cw", "dimension-keys", url.Values{"namespace": {"AWS/RDS"}}, &items); err != nil {
		t.Fatalf("err: %v", err)
	}
	if calls != 2 || len(items) != 1 {
		t.Fatalf("calls=%d items=%v", calls, items)
	}
}
