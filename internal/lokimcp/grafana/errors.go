package grafana

import "fmt"

type GrafanaError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *GrafanaError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("grafana error (HTTP %d): %s: %v", e.StatusCode, e.Message, e.Err)
	}
	return fmt.Sprintf("grafana error (HTTP %d): %s", e.StatusCode, e.Message)
}

func (e *GrafanaError) Unwrap() error { return e.Err }

func NewGrafanaError(statusCode int, msg string, err error) *GrafanaError {
	return &GrafanaError{StatusCode: statusCode, Message: msg, Err: err}
}
