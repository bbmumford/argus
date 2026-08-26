// Package eventlog is the persistent, encrypted audit-event sink of the argus observability
// module. It persists audit events (who/what/when + PII) to a consumer-supplied store, with the
// PII fields (IP address, details) encrypted through a consumer-supplied encryptor — both
// injected interfaces, so the sink is store- and crypto-agnostic (extracted from HSTLES
// platform/logging, whose *sql.DB + security/encryption couplings are lifted here).
//
// Scope-agnostic: the event's Owner is an OPAQUE owner-scope (was a baked tenantID); the sink
// never interprets it. Capability-preserving: the source's user-coercion (system/unknown users
// stored as NULL, FK-safe), the mandatory PII encryption ("audit" domain), and the async console
// fallback are all retained.
package eventlog

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// AuditDomain is the encryption domain the source seals PII under; preserved verbatim so a
// consumer's Encryptor keys the same domain.
const AuditDomain = "audit"

// Event is one audit-event record. Owner is the opaque owner-scope. UserID is nil for
// system/unknown actors (FK-safe). IPAddress and Details arrive ALREADY encrypted when an
// encryptor is configured — the store persists them as given.
type Event struct {
	Owner     string  // opaque owner-scope (was tenantID) — the sink interprets nothing
	App       string
	Type      string
	Kind      string // "standard" (default) or "system"
	Desc      string
	TimeUnix  int64
	UserID    *string // nil ⇒ SQL NULL (system/unknown), avoiding FK violations
	IPAddress string  // encrypted under AuditDomain when an Encryptor is configured
	UserAgent string
	Details   string // encrypted under AuditDomain when an Encryptor is configured
}

// EventStore persists audit events. Injected — the consumer implements it over any store (an SQL
// events table, tursokv, …). Store-specific concerns (e.g. FK diagnostics) live in the impl; the
// user-coercion that PREVENTS the FK problem is done here, in the neutral layer.
type EventStore interface {
	WriteEvent(ctx context.Context, e Event) error
}

// Encryptor seals a plaintext field for a named domain. Injected — the consumer wires the real
// crypto (e.g. security/encryption). Returning an error fails the whole LogEvent CLOSED, so PII
// is never persisted in the clear on a crypto failure.
type Encryptor interface {
	Encrypt(plaintext, domain string) (ciphertext string, err error)
}

// EventLogger is the receiver-bound sink: a store + an encryptor, both required. Requiring the
// encryptor preserves the source's security posture (audit PII is always encrypted) — a
// deployment that genuinely wants plaintext must pass an explicit no-op encryptor, never omit it.
type EventLogger struct {
	store EventStore
	enc   Encryptor
	now   func() int64
}

// NewEventLogger builds the sink. store and enc are REQUIRED (fail-closed): a nil either way is
// rejected so PII can never be silently unencrypted or dropped. clock may be nil (defaults to
// wall-clock unix seconds).
func NewEventLogger(store EventStore, enc Encryptor, clock func() int64) (*EventLogger, error) {
	if store == nil {
		return nil, errors.New("eventlog: EventStore is required")
	}
	if enc == nil {
		return nil, errors.New("eventlog: Encryptor is required (pass an explicit no-op to store PII in the clear)")
	}
	if clock == nil {
		clock = func() int64 { return time.Now().Unix() }
	}
	return &EventLogger{store: store, enc: enc, now: clock}, nil
}

// LogEvent writes one audit event: coerces the user (system/unknown → NULL), encrypts the PII
// fields under AuditDomain, and persists via the store. Preserves the source's LogEvent exactly,
// store- and crypto-agnostic. Non-empty eventKind[0] overrides the default "standard".
func (l *EventLogger) LogEvent(ctx context.Context, owner, app, event, desc, userID, ipAddress, userAgent, details string, eventKind ...string) error {
	if l == nil || l.store == nil || l.enc == nil {
		return errors.New("eventlog: logger not configured")
	}
	kind := "standard"
	if len(eventKind) > 0 && eventKind[0] != "" {
		kind = eventKind[0]
	}

	// Coerce the user: NULL for system/unknown to avoid FK violations (the source's fix).
	trimmed := strings.TrimSpace(userID)
	var user *string
	if !(trimmed == "" || strings.EqualFold(trimmed, "system") || strings.EqualFold(trimmed, "nil") ||
		strings.EqualFold(trimmed, "null") || strings.EqualFold(kind, "system")) {
		user = &trimmed
	}

	// Encrypt PII under the audit domain; a crypto error fails the whole write CLOSED.
	var encIP, encDetails string
	var err error
	if ipAddress != "" {
		if encIP, err = l.enc.Encrypt(ipAddress, AuditDomain); err != nil {
			return fmt.Errorf("eventlog: encrypt ip_address: %w", err)
		}
	}
	if details != "" {
		if encDetails, err = l.enc.Encrypt(details, AuditDomain); err != nil {
			return fmt.Errorf("eventlog: encrypt details: %w", err)
		}
	}

	if err := l.store.WriteEvent(ctx, Event{
		Owner:     owner,
		App:       app,
		Type:      event,
		Kind:      kind,
		Desc:      desc,
		TimeUnix:  l.now(),
		UserID:    user,
		IPAddress: encIP,
		UserAgent: userAgent,
		Details:   encDetails,
	}); err != nil {
		return fmt.Errorf("eventlog: write event: %w", err)
	}
	return nil
}

// LogAsync is the source's deprecated console fallback (real logging routes to the event store).
// Preserved for backward compatibility; emits a single structured line via the standard logger.
func LogAsync(name, description, userID, ip, ua, meta string, eventKind ...string) {
	kind := "standard"
	if len(eventKind) > 0 && eventKind[0] != "" {
		kind = eventKind[0]
	}
	if name == "" {
		name = "log"
	}
	log.Printf("[%s] %s: %s | user=%s ip=%s ua=%s meta=%s kind=%s", kind, name, description, userID, ip, ua, meta, kind)
}
