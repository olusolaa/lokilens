package tempo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Search_SendsParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/search" {
			t.Errorf("path = %q", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("q") != `{status=error}` || q.Get("limit") != "5" || q.Get("spss") != "3" || q.Get("start") != "1700000000" {
			t.Errorf("params = %v", q)
		}
		w.Write([]byte(`{"traces":[{"traceID":"abc","rootServiceName":"wallet-service","durationMs":12}]}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	resp, err := c.Search(context.Background(), SearchRequest{Query: `{status=error}`, Start: time.Unix(1700000000, 0), End: time.Unix(1700003600, 0), Limit: 5, SpansPerSpanSet: 3})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(resp.Traces) != 1 || resp.Traces[0].DurationMs != 12 {
		t.Fatalf("traces = %+v", resp.Traces)
	}
}

func TestClient_Trace_UsesV2Path(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/traces/deadbeef" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("accept = %q", r.Header.Get("Accept"))
		}
		w.Write([]byte(`{"trace":{"resourceSpans":[]}}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	if _, err := c.Trace(context.Background(), TraceRequest{TraceID: "deadbeef"}); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestClient_TagValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/search/tag/resource.service.name/values" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"tagValues":[{"type":"string","value":"wallet-service"}]}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	resp, err := c.TagValues(context.Background(), TagValuesRequest{Tag: "resource.service.name"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(resp.TagValues) != 1 || resp.TagValues[0].Value != "wallet-service" {
		t.Fatalf("values = %+v", resp.TagValues)
	}
}

func TestClient_PropagatesNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("trace not found"))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	if _, err := c.Trace(context.Background(), TraceRequest{TraceID: "missing"}); err == nil {
		t.Fatal("expected error on HTTP 404")
	}
}
