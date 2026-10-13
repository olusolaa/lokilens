package tempo

import (
	"encoding/json"
	"strings"
	"time"
)

type SearchRequest struct {
	Query           string
	Start           time.Time
	End             time.Time
	Limit           int
	SpansPerSpanSet int
}

type TagsRequest struct {
	Scope string
	Start time.Time
	End   time.Time
}

type TagValuesRequest struct {
	Tag   string
	Query string
	Start time.Time
	End   time.Time
}

type TraceRequest struct {
	TraceID string
	Start   time.Time
	End     time.Time
}

type SearchResponse struct {
	Traces []SearchTrace `json:"traces"`
}

type SearchTrace struct {
	TraceID           string                  `json:"traceID"`
	RootServiceName   string                  `json:"rootServiceName"`
	RootTraceName     string                  `json:"rootTraceName"`
	StartTimeUnixNano string                  `json:"startTimeUnixNano"`
	DurationMs        int64                   `json:"durationMs"`
	SpanSets          []SpanSet               `json:"spanSets"`
	ServiceStats      map[string]ServiceStats `json:"serviceStats"`
}

type ServiceStats struct {
	SpanCount  int `json:"spanCount"`
	ErrorCount int `json:"errorCount"`
}

type SpanSet struct {
	Spans   []SearchSpan `json:"spans"`
	Matched int          `json:"matched"`
}

type SearchSpan struct {
	SpanID            string      `json:"spanID"`
	Name              string      `json:"name"`
	StartTimeUnixNano string      `json:"startTimeUnixNano"`
	DurationNanos     string      `json:"durationNanos"`
	Attributes        []Attribute `json:"attributes"`
}

type TagsResponse struct {
	Scopes []TagScope `json:"scopes"`
}

type TagScope struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type TagValuesResponse struct {
	TagValues []TagValue `json:"tagValues"`
}

type TagValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type TraceResponse struct {
	Trace struct {
		ResourceSpans []ResourceSpans `json:"resourceSpans"`
	} `json:"trace"`
}

type ResourceSpans struct {
	Resource struct {
		Attributes []Attribute `json:"attributes"`
	} `json:"resource"`
	ScopeSpans []struct {
		Spans []OTLPSpan `json:"spans"`
	} `json:"scopeSpans"`
}

type OTLPSpan struct {
	SpanID            string      `json:"spanId"`
	ParentSpanID      string      `json:"parentSpanId"`
	Name              string      `json:"name"`
	Kind              string      `json:"kind"`
	StartTimeUnixNano string      `json:"startTimeUnixNano"`
	EndTimeUnixNano   string      `json:"endTimeUnixNano"`
	Attributes        []Attribute `json:"attributes"`
	Status            struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
}

type Attribute struct {
	Key   string         `json:"key"`
	Value AttributeValue `json:"value"`
}

type AttributeValue struct {
	StringValue *string         `json:"stringValue,omitempty"`
	IntValue    *string         `json:"intValue,omitempty"`
	BoolValue   *bool           `json:"boolValue,omitempty"`
	DoubleValue *float64        `json:"doubleValue,omitempty"`
	ArrayValue  json.RawMessage `json:"arrayValue,omitempty"`
}

func (v AttributeValue) String() string {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.IntValue != nil:
		return *v.IntValue
	case v.BoolValue != nil:
		if *v.BoolValue {
			return "true"
		}
		return "false"
	case v.DoubleValue != nil:
		b, _ := json.Marshal(*v.DoubleValue)
		return string(b)
	case len(v.ArrayValue) > 0:
		return strings.TrimSpace(string(v.ArrayValue))
	}
	return ""
}
