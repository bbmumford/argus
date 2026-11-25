// Package eventlog is the persistent, encrypted audit-event sink of the argus observability
// module. It persists audit events (who/what/when + PII) to a consumer-supplied store, with the
// PII fields (IP address, details) encrypted through a consumer-supplied encryptor — both
// injected interfaces, so the sink is store- and crypto-agnostic.
//
// Every event is filed under a partition, and a subject when a person acted. Both are opaque
// strings the sink never interprets; an event with no partition is refused before anything is
// encrypted or written.
package eventlog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AuditDomain is the encryption domain PII is sealed under, so a consumer's Encryptor keys one
// domain for every audit field.
const AuditDomain = "audit"

// ErrPartitionRequired is returned by LogEvent for an empty partition. The check runs before any
// field is encrypted or the store is reached, so no event is ever written unpartitioned.
var ErrPartitionRequired = errors.New("eventlog: partition is required")

// Event is one audit-event record. Subject is nil for system/unknown actors, so a store with a
// foreign key on it writes NULL rather than a dangling id. IPAddress and Details arrive ALREADY
// encrypted — the store persists them as given.
type Event struct {
	Partition string
	App       string
	Type      string
	Kind      string // "standard" (default) or "system"
	Desc      string
	TimeUnix  int64
	Subject   *string // nil ⇒ SQL NULL (system/unknown actor)
	IPAddress string  // encrypted under AuditDomain
	UserAgent string
	Details   string // encrypted under AuditDomain
}

// EventStore persists audit events. Injected — the consumer implements it over any store (an SQL
// events table, tursokv, …). Store-specific concerns (e.g. FK diagnostics) live in the impl; the
// subject coercion that prevents the FK problem is done here, in the neutral layer.
type EventStore interface {
	WriteEvent(ctx context.Context, e Event) error
}

// Encryptor seals a plaintext field for a named domain. Injected — the consumer wires the real
// crypto. Returning an error fails the whole LogEvent CLOSED, so PII is never persisted in the
// clear on a crypto failure.
type Encryptor interface {
	Encrypt(plaintext, domain string) (ciphertext string, err error)
}

// EventLogger is the receiver-bound sink: a store + an encryptor, both required. Requiring the
// encryptor keeps audit PII always encrypted — a deployment that genuinely wants plaintext must
// pass an explicit no-op encryptor, never omit it.
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

// LogEvent writes one audit event filed under partition: it refuses an empty partition, coerces
// the subject (system/unknown → NULL), encrypts the PII fields under AuditDomain, and persists via
// the store. Non-empty eventKind[0] overrides the default "standard".
func (l *EventLogger) LogEvent(ctx context.Context, partition, app, event, desc, subject, ipAddress, userAgent, details string, eventKind ...string) error {
	if l == nil || l.store == nil || l.enc == nil {
		return errors.New("eventlog: logger not configured")
	}
	if partition == "" {
		return ErrPartitionRequired
	}
	kind := "standard"
	if len(eventKind) > 0 && eventKind[0] != "" {
		kind = eventKind[0]
	}

	// NULL for system/unknown actors, so a foreign key on the subject never sees a placeholder id.
	trimmed := strings.TrimSpace(subject)
	var actor *string
	if trimmed != "" && !strings.EqualFold(trimmed, "system") && !strings.EqualFold(trimmed, "nil") &&
		!strings.EqualFold(trimmed, "null") && !strings.EqualFold(kind, "system") {
		actor = &trimmed
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
		Partition: partition,
		App:       app,
		Type:      event,
		Kind:      kind,
		Desc:      desc,
		TimeUnix:  l.now(),
		Subject:   actor,
		IPAddress: encIP,
		UserAgent: userAgent,
		Details:   encDetails,
	}); err != nil {
		return fmt.Errorf("eventlog: write event: %w", err)
	}
	return nil
}
