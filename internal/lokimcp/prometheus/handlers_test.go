package prometheus

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/olusolaa/lokilens/internal/lokimcp/audit"
	"github.com/olusolaa/lokilens/internal/lokimcp/loki"
)

type fakeClient struct {
	labelValues []string
	matrixJSON  string
}

func (f *fakeClient) Query(ctx context.Context, req InstantQueryRequest) (*loki.QueryResponse, error) {
	return &loki.QueryResponse{Data: loki.QueryData{ResultType: "vector", Result: json.RawMessage(`[]`)}}, nil
}
func (f *fakeClient) QueryRange(ctx context.Context, req QueryRangeRequest) (*loki.QueryResponse, error) {
	return &loki.QueryResponse{Data: loki.QueryData{ResultType: "matrix", Result: json.RawMessage(f.matrixJSON)}}, nil
}
func (f *fakeClient) Labels(ctx context.Context, req LabelsRequest) (*loki.LabelsResponse, error) {
	return &loki.LabelsResponse{Data: []string{"job", "instance"}}, nil
}
func (f *fakeClient) LabelValues(ctx context.Context, req LabelValuesRequest) (*loki.LabelsResponse, error) {
	return &loki.LabelsResponse{Data: f.labelValues}, nil
}
func (f *fakeClient) Metadata(ctx context.Context, req MetadataRequest) (*MetadataResponse, error) {
	return &MetadataResponse{Data: map[string][]MetadataEntry{"up": {{Type: "gauge"}}}}, nil
}

func newTestHandlers(fc *fakeClient) *ToolHandlers {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewToolHandlers(fc, NewValidator(11000, 24*time.Hour), audit.New(logger))
}

func TestListMetrics(t *testing.T) {
	h := newTestHandlers(&fakeClient{labelValues: []string{"up", "go_goroutines"}})
	out, err := h.ListMetrics(context.Background(), ListMetricsInput{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Metrics) != 2 {
		t.Fatalf("metrics = %v", out.Metrics)
	}
}

func TestQueryRange_SummarizesSeries(t *testing.T) {
	matrix := `[{"metric":{"__name__":"up","job":"node"},"values":[[1609459200,"1"],[1609459260,"2"],[1609459320,"3"]]}]`
	h := newTestHandlers(&fakeClient{matrixJSON: matrix})
	out, err := h.QueryRange(context.Background(), QueryRangeInput{PromQL: "up", StartTime: "1h ago"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Series) != 1 {
		t.Fatalf("series = %d, want 1", len(out.Series))
	}
	if out.Series[0].Labels["job"] != "node" {
		t.Fatalf("labels = %v", out.Series[0].Labels)
	}
}

func TestQueryRange_RequiresPromQL(t *testing.T) {
	h := newTestHandlers(&fakeClient{})
	if _, err := h.QueryRange(context.Background(), QueryRangeInput{}); err == nil {
		t.Fatal("expected error for empty promql")
	}
}
