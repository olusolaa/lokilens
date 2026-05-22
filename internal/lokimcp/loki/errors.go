package loki

import "fmt"

type LokiError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *LokiError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("loki error (HTTP %d): %s: %v", e.StatusCode, e.Message, e.Err)
	}
	return fmt.Sprintf("loki error (HTTP %d): %s", e.StatusCode, e.Message)
}

func (e *LokiError) Unwrap() error { return e.Err }

func NewLokiError(statusCode int, msg string, err error) *LokiError {
	return &LokiError{StatusCode: statusCode, Message: msg, Err: err}
}
