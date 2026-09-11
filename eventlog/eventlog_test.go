package eventlog

import (
	"context"
	"errors"
	"testing"
)

type fakeStore struct {
	last   *Event
	writes int
	failer bool
}

func (f *fakeStore) WriteEvent(_ context.Context, e Event) error {
	if f.failer {
		return errors.New("store down")
	}
	f.writes++
	cp := e
	f.last = &cp
	return nil
}

type fakeEnc struct {
	calls  int
	failer bool
}

func (f *fakeEnc) Encrypt(pt, domain string) (string, error) {
	if f.failer {
		return "", errors.New("crypto down")
	}
	f.calls++
	return domain + ":" + pt, nil
}

func newLogger(t *testing.T, store EventStore, enc Encryptor) *EventLogger {
	t.Helper()
	l, err := NewEventLogger(store, enc, func() int64 { return 42 })
	if err != nil {
		t.Fatalf("NewEventLogger: %v", err)
	}
	return l
}

func TestNewEventLogger_RequiresStoreAndEncryptor(t *testing.T) {
	if _, err := NewEventLogger(nil, &fakeEnc{}, nil); err == nil {
		t.Fatal("nil store must be rejected")
	}
	if _, err := NewEventLogger(&fakeStore{}, nil, nil); err == nil {
		t.Fatal("nil encryptor must be rejected (never silently plaintext)")
	}
}

func TestLogEvent_SubjectCoercion(t *testing.T) {
	for _, tc := range []struct {
		subject, kind string
		wantNil       bool
	}{
		{"", "standard", true},
		{"system", "standard", true},
		{"nil", "standard", true},
		{"null", "standard", true},
		{"  ", "standard", true},
		{"real-user", "system", true}, // kind=system coerces even a real subject
		{"real-user", "standard", false},
	} {
		store := &fakeStore{}
		l := newLogger(t, store, &fakeEnc{})
		if err := l.LogEvent(context.Background(), "acme", "app", "ev", "d", tc.subject, "", "", "", tc.kind); err != nil {
			t.Fatalf("LogEvent(%q,%q): %v", tc.subject, tc.kind, err)
		}
		gotNil := store.last.Subject == nil
		if gotNil != tc.wantNil {
			t.Fatalf("subject=%q kind=%q → Subject nil=%v, want %v", tc.subject, tc.kind, gotNil, tc.wantNil)
		}
		if !tc.wantNil && *store.last.Subject != "real-user" {
			t.Fatalf("expected real-user, got %q", *store.last.Subject)
		}
	}
}

func TestLogEvent_EncryptsPIIUnderAuditDomain(t *testing.T) {
	store := &fakeStore{}
	enc := &fakeEnc{}
	l := newLogger(t, store, enc)
	if err := l.LogEvent(context.Background(), "acme", "app", "login", "desc", "u1", "1.2.3.4", "curl", "{\"k\":1}"); err != nil {
		t.Fatal(err)
	}
	if store.last.IPAddress != AuditDomain+":1.2.3.4" {
		t.Fatalf("IP not encrypted under audit domain: %q", store.last.IPAddress)
	}
	if store.last.Details != AuditDomain+":{\"k\":1}" {
		t.Fatalf("details not encrypted: %q", store.last.Details)
	}
	if enc.calls != 2 {
		t.Fatalf("expected 2 encrypt calls (ip+details), got %d", enc.calls)
	}
	if store.last.Partition != "acme" || store.last.TimeUnix != 42 || store.last.Kind != "standard" {
		t.Fatalf("event shape wrong: %+v", store.last)
	}
}

func TestLogEvent_EmptyPIINotEncrypted(t *testing.T) {
	store := &fakeStore{}
	enc := &fakeEnc{}
	l := newLogger(t, store, enc)
	if err := l.LogEvent(context.Background(), "acme", "app", "ev", "d", "u1", "", "ua", ""); err != nil {
		t.Fatal(err)
	}
	if enc.calls != 0 {
		t.Fatalf("empty IP+details must not call encrypt; got %d", enc.calls)
	}
}

func TestLogEvent_CryptoFailure_FailsClosed(t *testing.T) {
	store := &fakeStore{}
	l := newLogger(t, store, &fakeEnc{failer: true})
	if err := l.LogEvent(context.Background(), "acme", "app", "ev", "d", "u1", "1.2.3.4", "ua", "x"); err == nil {
		t.Fatal("a crypto failure must fail the write CLOSED")
	}
	if store.writes != 0 {
		t.Fatal("PII must NEVER be persisted when encryption fails")
	}
}

// TestLogEvent_RefusesAnEmptyPartition: the refusal must come before the encryptor or the store is
// reached, and the same call with a partition must write.
func TestLogEvent_RefusesAnEmptyPartition(t *testing.T) {
	store := &fakeStore{}
	enc := &fakeEnc{}
	l := newLogger(t, store, enc)
	if err := l.LogEvent(context.Background(), "", "app", "ev", "d", "u1", "1.2.3.4", "ua", "x"); !errors.Is(err, ErrPartitionRequired) {
		t.Fatalf("LogEvent with no partition = %v, want ErrPartitionRequired", err)
	}
	if store.writes != 0 || enc.calls != 0 {
		t.Fatalf("a refused event reached the encryptor (%d) or the store (%d)", enc.calls, store.writes)
	}
	if err := l.LogEvent(context.Background(), "acme", "app", "ev", "d", "u1", "1.2.3.4", "ua", "x"); err != nil {
		t.Fatalf("LogEvent in a partition: %v", err)
	}
	if store.writes != 1 || store.last.Partition != "acme" {
		t.Fatalf("the partitioned event was not written as given: writes=%d last=%+v", store.writes, store.last)
	}
}
