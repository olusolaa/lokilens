package prometheus

import "time"

// InstantQueryRequest is a PromQL instant query (/api/v1/query).
type InstantQueryRequest struct {
	Query string
	Time  time.Time // zero = server "now"
}

// QueryRangeRequest is a PromQL range query (/api/v1/query_range).
type QueryRangeRequest struct {
	Query string
	Start time.Time
	End   time.Time
	Step  string // duration string, e.g. "30s", "1m"
}

// LabelsRequest requests label names (/api/v1/labels).
type LabelsRequest struct {
	Start time.Time
	End   time.Time
	Match string // optional series selector, e.g. {job="node"}
}

// LabelValuesRequest requests values of one label (/api/v1/label/<name>/values).
type LabelValuesRequest struct {
	LabelName string
	Start     time.Time
	End       time.Time
	Match     string
}

// MetadataRequest requests metric metadata (/api/v1/metadata).
type MetadataRequest struct {
	Metric string // optional; empty = all metrics
}

// MetadataEntry is one HELP/TYPE/unit record for a metric.
type MetadataEntry struct {
	Type string `json:"type"`
	Help string `json:"help"`
	Unit string `json:"unit"`
}

// MetadataResponse is the /api/v1/metadata response.
type MetadataResponse struct {
	Status string                     `json:"status"`
	Data   map[string][]MetadataEntry `json:"data"`
}
