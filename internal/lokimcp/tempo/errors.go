package tempo

import "fmt"

type TempoError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *TempoError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("tempo error (HTTP %d): %s: %v", e.StatusCode, e.Message, e.Err)
	}
	return fmt.Sprintf("tempo error (HTTP %d): %s", e.StatusCode, e.Message)
}

func (e *TempoError) Unwrap() error { return e.Err }

func NewTempoError(statusCode int, msg string, err error) *TempoError {
	return &TempoError{StatusCode: statusCode, Message: msg, Err: err}
}
