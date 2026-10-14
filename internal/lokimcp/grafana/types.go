package grafana

import (
	"fmt"
	"time"
)

type QueryRequest struct {
	From    time.Time
	To      time.Time
	Queries []map[string]any
}

type QueryResponse struct {
	Results map[string]QueryResult `json:"results"`
}

type QueryResult struct {
	Status int     `json:"status"`
	Error  string  `json:"error"`
	Frames []Frame `json:"frames"`
}

type Frame struct {
	Schema struct {
		Name   string  `json:"name"`
		Fields []Field `json:"fields"`
		Meta   struct {
			ExecutedQueryString string `json:"executedQueryString"`
		} `json:"meta"`
	} `json:"schema"`
	Data struct {
		Values [][]any `json:"values"`
	} `json:"data"`
}

type Field struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

type DataSource struct {
	UID      string         `json:"uid"`
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	JSONData map[string]any `json:"jsonData"`
}

func (r *QueryResponse) Single(refID string) (QueryResult, error) {
	res, ok := r.Results[refID]
	if !ok {
		return res, fmt.Errorf("grafana returned no result for query %s", refID)
	}
	if res.Error != "" {
		return res, fmt.Errorf("%s", truncate(res.Error, 600))
	}
	return res, nil
}

func (f Frame) RowCount() int {
	if len(f.Data.Values) == 0 {
		return 0
	}
	return len(f.Data.Values[0])
}

func (f Frame) Cell(field, row int) any {
	if field >= len(f.Data.Values) || row >= len(f.Data.Values[field]) {
		return nil
	}
	v := f.Data.Values[field][row]
	if field < len(f.Schema.Fields) && f.Schema.Fields[field].Type == "time" {
		if ms, ok := v.(float64); ok {
			return time.UnixMilli(int64(ms)).UTC().Format(time.RFC3339)
		}
	}
	return v
}
