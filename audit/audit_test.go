package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
)

// capture installs a JSON handler on slog.Default writing to buf, and restores the prior default.
func capture(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	return buf, func() { slog.SetDefault(prev) }
}

func lastRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	var m map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &m); err != nil {
		t.Fatalf("bad json: %v (%q)", err, buf.String())
	}
	return m
}

func TestSecurityDeny_Vocabulary(t *testing.T) {
	buf, restore := capture(t)
	defer restore()
	log := New("platform.security.auth")
	log.SecurityDeny(context.Background(), "denied", "org_access_denied", "user-1", errors.New("boom"))
	m := lastRecord(t, buf)
	if m[KeySubsystem] != "platform.security.auth" {
		t.Fatalf("subsystem=%v", m[KeySubsystem])
	}
	if m[KeyReason] != "org_access_denied" {
		t.Fatalf("reason=%v", m[KeyReason])
	}
	if m[KeyDecision] != DecisionDeny {
		t.Fatalf("decision=%v, want deny", m[KeyDecision])
	}
	if m[KeyActor] != "user-1" {
		t.Fatalf("actor=%v", m[KeyActor])
	}
	if _, ok := m[KeyErr]; !ok {
		t.Fatalf("err attr missing: %v", m)
	}
}

func TestSecurityAuditAndChallenge_Decisions(t *testing.T) {
	buf, restore := capture(t)
	defer restore()
	log := New("s")
	log.SecurityAudit(context.Background(), "ok", "session_mint", "u")
	if got := lastRecord(t, buf)[KeyDecision]; got != DecisionAllow {
		t.Fatalf("audit decision=%v, want allow", got)
	}
	log.SecurityChallenge(context.Background(), "mfa", "mfa_required", "u")
	if got := lastRecord(t, buf)[KeyDecision]; got != DecisionChallenge {
		t.Fatalf("challenge decision=%v, want challenge", got)
	}
}

// TestTraceHook proves the trace coupling is INJECTABLE (capability preserved when wired) and
// AGNOSTIC by default (nil hook → dropped, the source's zero-cost no-trace path).
func TestTraceHook_InjectableAndAgnostic(t *testing.T) {
	buf, restore := capture(t)
	defer restore()
	log := New("s")

	TraceFromContext = nil
	log.Info(context.Background(), "no-trace")
	if _, ok := lastRecord(t, buf)[KeyTrace]; ok {
		t.Fatal("nil hook must not emit a trace attribute (agnostic default)")
	}

	TraceFromContext = func(context.Context) string { return "trace-123" }
	defer func() { TraceFromContext = nil }()
	log.Info(context.Background(), "traced")
	if got := lastRecord(t, buf)[KeyTrace]; got != "trace-123" {
		t.Fatalf("a wired hook must inject the trace; got %v", got)
	}

	TraceFromContext = func(context.Context) string { return "" }
	log.Info(context.Background(), "empty-trace")
	if _, ok := lastRecord(t, buf)[KeyTrace]; ok {
		t.Fatal("an empty trace id must be dropped (zero-cost path)")
	}
}

func TestToAttrSlice_PairsAndAttrs(t *testing.T) {
	buf, restore := capture(t)
	defer restore()
	log := New("s")
	log.Info(context.Background(), "m", "custom_key", "custom_val", slog.String("attr_key", "attr_val"))
	m := lastRecord(t, buf)
	if m["custom_key"] != "custom_val" {
		t.Fatalf("(key,value) pair not emitted: %v", m)
	}
	if m["attr_key"] != "attr_val" {
		t.Fatalf("slog.Attr not emitted: %v", m)
	}
}

func TestNilLogger_SubsystemSafe(t *testing.T) {
	var l *Logger
	if l.Subsystem() != "" {
		t.Fatal("nil logger Subsystem() must be empty, not panic")
	}
}
