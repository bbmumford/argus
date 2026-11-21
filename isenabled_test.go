/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package argus

import "testing"

// IsEnabled reports whether every tag is on, which DEBUG=* does as fully as the SetEnabled toggle.
func TestIsEnabledReportsEveryTagOn(t *testing.T) {
	t.Cleanup(func() { SetTags(nil); SetEnabled(false) })
	SetTags(nil)
	SetEnabled(false)
	t.Setenv("DEBUG", "pprof")
	if IsEnabled() {
		t.Fatal("IsEnabled with DEBUG=pprof = true, want false")
	}
	t.Setenv("DEBUG", "pprof, *")
	if !IsEnabled() {
		t.Fatal("IsEnabled with DEBUG holding * = false, want true")
	}
	t.Setenv("DEBUG", "")
	SetTags([]string{"*"})
	if !IsEnabled() {
		t.Fatal("IsEnabled under an override holding * = false, want true")
	}
	SetTags(nil)
	SetEnabled(true)
	if !IsEnabled() {
		t.Fatal("IsEnabled under SetEnabled(true) = false, want true")
	}
}
