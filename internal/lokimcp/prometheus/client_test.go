package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_LabelValues_ListMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/label/__name__/values" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"status":"success","data":["up","go_goroutines"]}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	resp, err := c.LabelValues(context.Background(), LabelValuesRequest{LabelName: "__name__"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(resp.Data) != 2 || resp.Data[0] != "up" {
		t.Fatalf("data = %v", resp.Data)
	}
}

func TestClient_QueryRange_SendsStep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("step"); got != "30s" {
			t.Errorf("step = %q, want 30s", got)
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"up"},"values":[[1609459200,"1"]]}]}}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	resp, err := c.QueryRange(context.Background(), QueryRangeRequest{
		Query: "up", Start: time.Unix(1609459200, 0), End: time.Unix(1609459800, 0), Step: "30s",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Data.ResultType != "matrix" {
		t.Fatalf("resultType = %q", resp.Data.ResultType)
	}
}

func TestClient_Metadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"up":[{"type":"gauge","help":"is up","unit":""}]}}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	resp, err := c.Metadata(context.Background(), MetadataRequest{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Data["up"][0].Type != "gauge" {
		t.Fatalf("type = %q", resp.Data["up"][0].Type)
	}
}

func TestClient_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"invalid query"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(ClientConfig{BaseURL: srv.URL})
	_, err := c.Query(context.Background(), InstantQueryRequest{Query: "!!!"})
	if err == nil {
		t.Fatal("expected error on HTTP 400")
	}
}
