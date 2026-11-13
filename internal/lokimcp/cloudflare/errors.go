package cloudflare

import "fmt"

type CloudflareError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *CloudflareError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("cloudflare error (HTTP %d): %s: %v", e.StatusCode, e.Message, e.Err)
	}
	return fmt.Sprintf("cloudflare error (HTTP %d): %s", e.StatusCode, e.Message)
}

func (e *CloudflareError) Unwrap() error { return e.Err }

func NewCloudflareError(statusCode int, msg string, err error) *CloudflareError {
	return &CloudflareError{StatusCode: statusCode, Message: msg, Err: err}
}
