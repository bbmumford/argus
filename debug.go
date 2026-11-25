/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package argus

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Logger provides namespaced debug logging with flag-deterministic output.
// Uses atomic.Bool for zero-cost isEnabled() checks — no lock contention
// on hot paths when debug is disabled (the common case in production).
type Logger struct {
	namespace string
	enabled   atomic.Bool
	logger    *log.Logger
}

var (
	globalLogger *log.Logger
	mu           sync.Mutex // protects loggers map + globalLogger write
	loggers      = make(map[string]*Logger)
)

func init() {
	// Initialize with stderr output and timestamp prefix
	globalLogger = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
}

// Configure replaces the debug log output destination and (optionally)
// flips the legacy global-enable switch on. The tag-list activation
// model is the source of truth for which namespaces emit — Configure
// is retained for back-compat with code that historically toggled all
// debug at once.
//
//	debug.Configure(true, os.Stderr)   // legacy: equivalent to DEBUG=*
//	debug.Configure(false, nil)        // legacy: silence everything regardless of DEBUG
func Configure(enabled bool, output io.Writer) {
	forceAllEnabled.Store(enabled)
	mu.Lock()
	if output != nil {
		globalLogger = log.New(output, "", log.LstdFlags|log.Lmicroseconds)
		for _, logger := range loggers {
			logger.logger = globalLogger
		}
	}
	mu.Unlock()
	refreshLoggers()
}

// SetEnabled flips the legacy "everything on" toggle. Equivalent to
// setting DEBUG=* — every Logger and every registered Feature becomes
// enabled. Use SetTags for finer-grained control.
func SetEnabled(enabled bool) {
	forceAllEnabled.Store(enabled)
	refreshLoggers()
}

// IsEnabled reports whether every namespace and feature is on: the
// SetEnabled / Configure toggle is set, or the effective DEBUG list holds
// "*". These are the two ways TagEnabled opens for every tag. Prefer
// TagEnabled("<namespace>") when checking a specific feature.
func IsEnabled() bool {
	if forceAllEnabled.Load() {
		return true
	}
	for _, t := range parsedTags() {
		if t == wildcardTag {
			return true
		}
	}
	return false
}

// New creates (or returns the cached) namespaced debug Logger. The
// logger is enabled iff TagEnabled(namespace) is true at call time;
// runtime changes via SetEnabled / SetTags refresh all cached loggers'
// states. Namespace conventions:
//
//	"mesh.vl1", "mesh.lad", "mesh.rpc"     — dotted hierarchy
//	"endpoint.help.monitoring"             — endpoint-scoped feature
//
// DEBUG=mesh.* enables all of mesh.vl1 + mesh.lad + mesh.rpc.
// DEBUG=mesh.vl1 enables only that one.
// DEBUG=* enables everything.
func New(namespace string) *Logger {
	mu.Lock()
	defer mu.Unlock()

	// Return cached logger if exists
	if logger, exists := loggers[namespace]; exists {
		return logger
	}

	// Create new logger
	logger := &Logger{
		namespace: namespace,
		logger:    globalLogger,
	}
	logger.enabled.Store(TagEnabled(namespace))

	loggers[namespace] = logger
	return logger
}

// refreshLoggers re-evaluates each cached Logger's enabled state
// against the current tag list (or forceAllEnabled override). Called
// from SetEnabled, SetTags, and Configure so a runtime change takes
// immediate effect across all existing loggers without callers needing
// to re-call debug.New(namespace).
func refreshLoggers() {
	mu.Lock()
	defer mu.Unlock()
	for ns, logger := range loggers {
		logger.enabled.Store(TagEnabled(ns))
	}
}

// Printf logs a formatted debug message if debug is enabled
func (l *Logger) Printf(format string, args ...interface{}) {
	if !l.isEnabled() {
		return
	}

	msg := fmt.Sprintf(format, args...)
	l.logger.Printf("[DEBUG:%s] %s", l.namespace, msg)
}

// Println logs a debug message if debug is enabled
func (l *Logger) Println(args ...interface{}) {
	if !l.isEnabled() {
		return
	}

	msg := fmt.Sprint(args...)
	l.logger.Printf("[DEBUG:%s] %s", l.namespace, msg)
}

// Logf is an alias for Printf
func (l *Logger) Logf(format string, args ...interface{}) {
	l.Printf(format, args...)
}

// Log is an alias for Println
func (l *Logger) Log(args ...interface{}) {
	l.Println(args...)
}

// isEnabled checks if debug is enabled for this logger.
// Zero-cost when disabled — single atomic load, no lock.
func (l *Logger) isEnabled() bool {
	return l.enabled.Load()
}

// SetNamespaceEnabled enables/disables debug for a specific namespace
// at runtime. Bypasses the tag list; intended for legacy callers and
// per-test fixtures. For env-driven control, set DEBUG=<namespace> or
// DEBUG=<prefix>.* and let TagEnabled drive activation.
func SetNamespaceEnabled(namespace string, enabled bool) {
	mu.Lock()
	defer mu.Unlock()

	if logger, exists := loggers[namespace]; exists {
		logger.enabled.Store(enabled)
	}
}

// GetNamespaces returns all registered debug namespaces
func GetNamespaces() []string {
	mu.Lock()
	defer mu.Unlock()

	namespaces := make([]string, 0, len(loggers))
	for ns := range loggers {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

// DebugInfo returns a summary of debug state
func DebugInfo() string {
	mu.Lock()
	defer mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "Force-all enabled: %v\n", forceAllEnabled.Load())
	fmt.Fprintf(&b, "DEBUG tags: %v\n", parsedTags())
	fmt.Fprintf(&b, "Registered namespaces: %d\n", len(loggers))
	for ns, logger := range loggers {
		fmt.Fprintf(&b, "  - %s: enabled=%v\n", ns, logger.enabled.Load())
	}
	fmt.Fprintf(&b, "Registered features: %d\n", len(features))
	for _, f := range features {
		fmt.Fprintf(&b, "  - %s: enabled=%v — %s\n", f.Tag, TagEnabled(f.Tag), f.Desc)
	}
	return b.String()
}

// Benchmark logs performance metrics if debug is enabled
func (l *Logger) Benchmark(name string, start time.Time) {
	if !l.isEnabled() {
		return
	}

	elapsed := time.Since(start)
	l.Printf("[BENCHMARK] %s took %v", name, elapsed)
}

// Trace logs entry/exit of functions if debug is enabled
func (l *Logger) Trace(funcName string) func() {
	if !l.isEnabled() {
		return func() {}
	}

	start := time.Now()
	l.Printf("[TRACE] → %s", funcName)

	return func() {
		l.Printf("[TRACE] ← %s (duration: %v)", funcName, time.Since(start))
	}
}
