/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package argus

import "testing"

// SetTags(nil) clears the override: TagEnabled, TagNamed and every cached Logger read the DEBUG
// variable again. An empty, non-nil list is still an override, under which no tag is on.
func TestSetTagsNilFallsBackToDEBUG(t *testing.T) {
	const tag = "argus.test.override"
	t.Setenv("DEBUG", tag)
	t.Cleanup(func() { SetTags(nil); SetEnabled(false) })
	SetEnabled(false)
	logger := New(tag)

	SetTags([]string{"argus.test.other"})
	if TagEnabled(tag) || logger.isEnabled() {
		t.Fatalf("with an override naming another tag, %q is on", tag)
	}
	SetTags(nil)
	if !TagEnabled(tag) || !TagNamed(tag) || !logger.isEnabled() {
		t.Fatalf("after SetTags(nil) with DEBUG=%q: TagEnabled=%v TagNamed=%v logger=%v, want all true",
			tag, TagEnabled(tag), TagNamed(tag), logger.isEnabled())
	}
	SetTags([]string{})
	if TagEnabled(tag) || logger.isEnabled() {
		t.Fatalf("under an empty override, %q is on", tag)
	}
}
