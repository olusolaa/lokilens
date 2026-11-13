package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClient_Query_SendsBearerAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("authorization = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["query"] != "{ viewer { zones { zoneTag } } }" {
			t.Errorf("body = %v err %v", body, err)
		}
		w.Write([]byte(`{"data":{"viewer":{"zones":[{"zoneTag":"abc"}]}},"errors":null}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL, APIToken: "secret-token"})
	resp, err := c.Query(context.Background(), "{ viewer { zones { zoneTag } } }")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(string(resp.Data), `"zoneTag":"abc"`) {
		t.Fatalf("data = %s", resp.Data)
	}
}

func TestClient_Query_SurfacesGraphQLErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":null,"errors":[{"message":"unknown field \"nope\""},{"message":"zone not authorized"}]}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	_, err := c.Query(context.Background(), "{ x }")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `unknown field "nope"`) || !strings.Contains(err.Error(), "zone not authorized") {
		t.Fatalf("err = %v", err)
	}
}

func TestClient_Query_RetriesOn500(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("boom"))
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["query"] != "{ x }" {
			t.Errorf("retry body = %v err %v", body, err)
		}
		w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	if _, err := c.Query(context.Background(), "{ x }"); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls = %d", got)
	}
}

func TestClient_Query_GivesUpAfterRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL, MaxRetries: 1})
	if _, err := c.Query(context.Background(), "{ x }"); err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls = %d", got)
	}
}

func TestClient_Query_PropagatesClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	_, err := c.Query(context.Background(), "{ x }")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}
