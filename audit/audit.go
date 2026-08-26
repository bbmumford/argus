// Package audit is a scope-agnostic structured-log adapter: it emits machine-parsable
// key/value records with a uniform field vocabulary (subsystem, reason, actor, peer, decision,
// err, trace) and named security-decision helpers, instead of free-form log strings.
//
// Extracted from HSTLES platform/observability/slog. The ONE coupling — automatic trace-ID
// propagation — is made agnostic via an injectable hook (TraceFromContext) rather than a baked
// dependency on a trace package: wire it once at boot (e.g. to loom/pkg/trace.FromContext) to
// keep the auto-trace capability; leave it nil and the trace attribute is simply dropped
// (the source's zero-cost no-trace path, preserved).
//
// Field vocabulary (canonical keys — do NOT invent new names):
//
//	subsystem  — dotted package path, e.g. "platform.security.middleware.auth"
//	reason     — snake_case machine token, e.g. "org_access_denied"
//	actor      — user_id | api_key_id | mesh_node_id — the principal being judged
//	peer       — mesh peer node ID (for mesh subsystems)
//	decision   — "allow" | "deny" | "challenge"
//	err        — the underlying error (nil-safe)
//	trace      — per-request trace ID (auto-injected from ctx when TraceFromContext is wired)
//
// Non-negotiable design principles (preserved from the source):
//   - Fail-closed on the security path. Emit the deny event AND return the deny; never
//     warn-and-continue.
//   - Observable failure. Every fail-closed branch calls SecurityDeny so the deny is visible in
//     dashboards even when the caller does not surface it.
//   - ctx propagation. The whole API accepts ctx; nil ctx is tolerated but the trace field drops.
//
// This package intentionally does not initialize the slog Default — each endpoint main installs a
// JSON handler (usually slog.NewJSONHandler(os.Stderr, nil)) at boot; the helpers read whatever
// handler is installed at call time.
package audit

import (
	"context"
	"log/slog"
)

// TraceFromContext, when set by the composition root, extracts the per-request trace ID from a
// context. Wire it to your trace package (e.g. loom/pkg/trace.FromContext) at boot to auto-inject
// the trace attribute; leave nil to drop trace (zero-cost no-trace path). Set once at startup
// before any logging; it is read without synchronization.
var TraceFromContext func(ctx context.Context) string

// Canonical field keys. Call sites SHOULD use these constants so a dashboard search for
// "reason=org_access_denied" hits every emitter.
const (
	KeySubsystem = "subsystem"
	KeyReason    = "reason"
	KeyActor     = "actor"
	KeyPeer      = "peer"
	KeyDecision  = "decision"
	KeyErr       = "err"
	KeyTrace     = "trace"
)

// Canonical decision values.
const (
	DecisionAllow     = "allow"
	DecisionDeny      = "deny"
	DecisionChallenge = "challenge"
)

// Logger is a subsystem-scoped structured logger. It carries the subsystem name so every emitted
// record includes it without the call site repeating it. Zero value is NOT usable — use New.
type Logger struct {
	subsystem string
}

// New returns a Logger bound to the given subsystem name (the dotted package path, e.g.
// "platform.security.middleware.auth", so prefix-aggregation across similar events works).
func New(subsystem string) *Logger {
	return &Logger{subsystem: subsystem}
}

// Subsystem returns the bound subsystem string.
func (l *Logger) Subsystem() string {
	if l == nil {
		return ""
	}
	return l.subsystem
}

// attrs prepends the subsystem attribute and (if a trace hook is wired and a trace is set) the
// trace attribute onto caller-supplied attrs. Nil-safe on ctx.
func (l *Logger) attrs(ctx context.Context, extra []any) []any {
	sub := ""
	if l != nil {
		sub = l.subsystem
	}
	out := make([]any, 0, 2+len(extra))
	if sub != "" {
		out = append(out, slog.String(KeySubsystem, sub))
	}
	if TraceFromContext != nil {
		if id := TraceFromContext(ctx); id != "" {
			out = append(out, slog.String(KeyTrace, id))
		}
	}
	out = append(out, extra...)
	return out
}

// Info emits an informational record. Prefer the named security helpers on the security path; use
// this for non-security state transitions (mesh promotion, cache warmup, etc.).
func (l *Logger) Info(ctx context.Context, msg string, attrs ...any) {
	slog.LogAttrs(ctx, slog.LevelInfo, msg, toAttrSlice(l.attrs(ctx, attrs))...)
}

// Warn emits a warning record. Use for recoverable degradation.
func (l *Logger) Warn(ctx context.Context, msg string, attrs ...any) {
	slog.LogAttrs(ctx, slog.LevelWarn, msg, toAttrSlice(l.attrs(ctx, attrs))...)
}

// Error emits an error record. Use for unrecoverable failures on non-security paths. Security
// paths MUST use SecurityDeny so dashboards can correlate on decision=deny.
func (l *Logger) Error(ctx context.Context, msg string, err error, attrs ...any) {
	all := l.attrs(ctx, attrs)
	if err != nil {
		all = append(all, slog.Any(KeyErr, err))
	}
	slog.LogAttrs(ctx, slog.LevelError, msg, toAttrSlice(all)...)
}

// SecurityDeny emits a canonical security deny event — the mandatory entry point for every
// fail-closed branch on an authorization/authentication path; the (subsystem, reason,
// decision=deny) triple is what alerting dashboards key off of. err is optional (nil for
// policy-driven denies, the underlying error for infrastructure-driven fail-closed).
func (l *Logger) SecurityDeny(ctx context.Context, msg string, reason string, actor string, err error, attrs ...any) {
	extras := []any{
		slog.String(KeyReason, reason),
		slog.String(KeyDecision, DecisionDeny),
	}
	if actor != "" {
		extras = append(extras, slog.String(KeyActor, actor))
	}
	if err != nil {
		extras = append(extras, slog.Any(KeyErr, err))
	}
	extras = append(extras, attrs...)
	slog.LogAttrs(ctx, slog.LevelError, msg, toAttrSlice(l.attrs(ctx, extras))...)
}

// SecurityAudit emits a canonical audit-grade record (successful handoff redemption, session
// mint, MFA verification) at Info level with decision=allow, so one decision facet spans allow
// and deny events.
func (l *Logger) SecurityAudit(ctx context.Context, msg string, reason string, actor string, attrs ...any) {
	extras := []any{
		slog.String(KeyReason, reason),
		slog.String(KeyDecision, DecisionAllow),
	}
	if actor != "" {
		extras = append(extras, slog.String(KeyActor, actor))
	}
	extras = append(extras, attrs...)
	slog.LogAttrs(ctx, slog.LevelInfo, msg, toAttrSlice(l.attrs(ctx, extras))...)
}

// SecurityChallenge emits the canonical challenge record (2FA prompt required, MFA redirect) at
// Info level with decision=challenge, so dashboards separate "escalated to user" from allow/deny.
func (l *Logger) SecurityChallenge(ctx context.Context, msg string, reason string, actor string, attrs ...any) {
	extras := []any{
		slog.String(KeyReason, reason),
		slog.String(KeyDecision, DecisionChallenge),
	}
	if actor != "" {
		extras = append(extras, slog.String(KeyActor, actor))
	}
	extras = append(extras, attrs...)
	slog.LogAttrs(ctx, slog.LevelInfo, msg, toAttrSlice(l.attrs(ctx, extras))...)
}

// toAttrSlice normalises the variadic attrs so LogAttrs never receives a bare (key,value) pair —
// it only speaks slog.Attr. slog.Any is the fallback for anything not already an Attr.
func toAttrSlice(in []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(in))
	i := 0
	for i < len(in) {
		v := in[i]
		if a, ok := v.(slog.Attr); ok {
			out = append(out, a)
			i++
			continue
		}
		if key, ok := v.(string); ok && i+1 < len(in) {
			out = append(out, slog.Any(key, in[i+1]))
			i += 2
			continue
		}
		out = append(out, slog.Any("value", v))
		i++
	}
	return out
}
