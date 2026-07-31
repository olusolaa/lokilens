package prometheus

import "fmt"

type PromError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *PromError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("prometheus error (HTTP %d): %s: %v", e.StatusCode, e.Message, e.Err)
	}
	return fmt.Sprintf("prometheus error (HTTP %d): %s", e.StatusCode, e.Message)
}

func (e *PromError) Unwrap() error { return e.Err }

func NewPromError(statusCode int, msg string, err error) *PromError {
	return &PromError{StatusCode: statusCode, Message: msg, Err: err}
}
