package agent

import "fmt"

// ErrorCode identifies agent error types.
type ErrorCode int

const (
	ErrConfigInvalid ErrorCode = iota
	ErrConnectionFailed
	ErrCollectorFailed
	ErrResourceExceeded
	ErrUpdateFailed
)

// AgentError wraps errors with code and retry hint.
type AgentError struct {
	Code    ErrorCode
	Message string
	Cause   error
	Retry   bool
}

func (e *AgentError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *AgentError) Unwrap() error { return e.Cause }
