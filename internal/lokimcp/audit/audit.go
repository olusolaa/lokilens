package audit

import "log/slog"

// Logger provides structured audit trail logging. All events are emitted under
// the "audit" group so they can be easily filtered from operational logs.
type Logger struct {
	l *slog.Logger
}

// New creates an audit logger that prefixes all attributes with "audit.".
func New(base *slog.Logger) *Logger {
	return &Logger{l: base.WithGroup("audit")}
}

// MessageReceived logs an incoming user message.
// Source is one of: "dm", "mention", "thread_followup".
func (a *Logger) MessageReceived(user, channel, sessionID, source string) {
	a.l.Info("message_received",
		"event", "message_received",
		"user", user,
		"channel", channel,
		"session_id", sessionID,
		"source", source,
	)
}

// PromptInjectionBlocked logs a blocked prompt injection attempt.
func (a *Logger) PromptInjectionBlocked(user, channel string) {
	a.l.Warn("prompt_injection_blocked",
		"event", "prompt_injection_blocked",
		"user", user,
		"channel", channel,
	)
}

// MaxTurnsExceeded logs when a conversation exceeds the turn limit.
func (a *Logger) MaxTurnsExceeded(user, channel, sessionID string, turns int) {
	a.l.Warn("max_turns_exceeded",
		"event", "max_turns_exceeded",
		"user", user,
		"channel", channel,
		"session_id", sessionID,
		"turns", turns,
	)
}

// CircuitBreakerTripped logs when the circuit breaker rejects a request.
func (a *Logger) CircuitBreakerTripped(user, channel string) {
	a.l.Warn("circuit_breaker_tripped",
		"event", "circuit_breaker_tripped",
		"user", user,
		"channel", channel,
	)
}

// AgentStarted logs the beginning of an agent execution.
func (a *Logger) AgentStarted(user, channel, sessionID string) {
	a.l.Info("agent_started",
		"event", "agent_started",
		"user", user,
		"channel", channel,
		"session_id", sessionID,
	)
}

// AgentCompleted logs a successful agent execution with duration.
func (a *Logger) AgentCompleted(user, channel, sessionID string, durationMS int64) {
	a.l.Info("agent_completed",
		"event", "agent_completed",
		"user", user,
		"channel", channel,
		"session_id", sessionID,
		"duration_ms", durationMS,
	)
}

// AgentFailed logs a failed agent execution with duration and error.
func (a *Logger) AgentFailed(user, channel, sessionID string, durationMS int64, err error) {
	a.l.Error("agent_failed",
		"event", "agent_failed",
		"user", user,
		"channel", channel,
		"session_id", sessionID,
		"duration_ms", durationMS,
		"error", err,
	)
}

// PIIRedacted logs that PII patterns were redacted from a response.
func (a *Logger) PIIRedacted(channel, sessionID string, patternCount int) {
	a.l.Warn("pii_redacted",
		"event", "pii_redacted",
		"channel", channel,
		"session_id", sessionID,
		"pattern_count", patternCount,
	)
}

// ToolInvoked logs a successful tool invocation with duration and extra attributes.
func (a *Logger) ToolInvoked(tool string, durationMS int64, attrs ...slog.Attr) {
	base := []any{
		"event", "tool_invoked",
		"tool", tool,
		"duration_ms", durationMS,
	}
	for _, attr := range attrs {
		base = append(base, attr)
	}
	a.l.Info("tool_invoked", base...)
}

// ToolFailed logs a failed tool invocation.
func (a *Logger) ToolFailed(tool string, durationMS int64, err error) {
	a.l.Error("tool_failed",
		"event", "tool_failed",
		"tool", tool,
		"duration_ms", durationMS,
		"error", err,
	)
}

// SessionCreated logs the creation of a new ADK session.
func (a *Logger) SessionCreated(user, sessionID string) {
	a.l.Info("session_created",
		"event", "session_created",
		"user", user,
		"session_id", sessionID,
	)
}
