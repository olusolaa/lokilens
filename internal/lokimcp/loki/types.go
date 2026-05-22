package loki

import (
	"encoding/json"
	"fmt"
	"time"
)

// QueryRangeRequest represents a Loki range query request.
type QueryRangeRequest struct {
	Query     string
	Start     time.Time
	End       time.Time
	Limit     int
	Direction string // "forward" or "backward"
	Step      string // for metric queries, e.g., "1m", "5m"
}

// InstantQueryRequest represents a Loki instant query request.
type InstantQueryRequest struct {
	Query     string
	Time      time.Time
	Limit     int
	Direction string
}

// LabelsRequest represents a request for label names.
type LabelsRequest struct {
	Start time.Time
	End   time.Time
}

// LabelValuesRequest represents a request for values of a specific label.
type LabelValuesRequest struct {
	LabelName string
	Start     time.Time
	End       time.Time
	Query     string // optional stream selector to scope results
}

// QueryResponse is the top-level Loki API response.
type QueryResponse struct {
	Status string    `json:"status"`
	Data   QueryData `json:"data"`
}

// QueryData contains the result payload.
type QueryData struct {
	ResultType string          `json:"resultType"` // "streams", "matrix", "vector"
	Result     json.RawMessage `json:"result"`
	Stats      QueryStats      `json:"stats"`
}

// QueryStats contains execution statistics.
type QueryStats struct {
	Summary StatsSummary `json:"summary"`
}

// StatsSummary contains query performance metrics.
type StatsSummary struct {
	BytesProcessedPerSecond int     `json:"bytesProcessedPerSecond"`
	LinesProcessedPerSecond int     `json:"linesProcessedPerSecond"`
	TotalBytesProcessed     int     `json:"totalBytesProcessed"`
	TotalLinesProcessed     int     `json:"totalLinesProcessed"`
	ExecTime                float64 `json:"execTime"`
}

// Stream represents a log stream with its entries.
type Stream struct {
	Labels map[string]string `json:"stream"`
	Values [][]string        `json:"values"` // [[nanosecond_ts, log_line], ...]
}

// SamplePair represents a Loki/Prometheus [timestamp, value] tuple.
// Loki returns these as [json_number, json_string] — e.g., [1609459200.123, "1234.5"].
type SamplePair struct {
	Timestamp float64
	Value     string
}

// UnmarshalJSON handles the mixed [number, string] JSON tuple from Loki.
func (sp *SamplePair) UnmarshalJSON(data []byte) error {
	var raw [2]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("sample pair: %w", err)
	}
	if err := json.Unmarshal(raw[0], &sp.Timestamp); err != nil {
		return fmt.Errorf("sample pair timestamp: %w", err)
	}
	if err := json.Unmarshal(raw[1], &sp.Value); err != nil {
		return fmt.Errorf("sample pair value: %w", err)
	}
	return nil
}

// MatrixSeries represents a metric time series.
type MatrixSeries struct {
	Metric map[string]string `json:"metric"`
	Values []SamplePair      `json:"values"`
}

// VectorSample represents a single instant metric value.
type VectorSample struct {
	Metric map[string]string `json:"metric"`
	Value  SamplePair        `json:"value"`
}

// LabelsResponse is the response for label name/value queries.
type LabelsResponse struct {
	Status string   `json:"status"`
	Data   []string `json:"data"`
}
