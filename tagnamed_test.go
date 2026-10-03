/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package argus

import "testing"

// TagNamed opens only for the exact tag: the "*" wildcard, a prefix wildcard
// covering the tag and the global toggle each leave it closed, though each opens
// TagEnabled for the same tag.
func TestTagNamed_OpensOnlyForTheExactTag(t *testing.T) {
	t.Cleanup(func() { SetTags(nil); SetEnabled(false) })
	const tag = "endpoint.help.diag"
	for _, tags := range [][]string{{"*"}, {"endpoint.help.*"}, {"endpoint.*"}, {"endpoint.help.diag2"}, nil} {
		SetTags(tags)
		if TagNamed(tag) {
			t.Fatalf("TagNamed(%q) with DEBUG=%v = true, want false", tag, tags)
		}
	}
	SetTags([]string{"endpoint.help.*"})
	if !TagEnabled(tag) {
		t.Fatalf("TagEnabled(%q) under its prefix wildcard = false; the comparison this test draws needs it true", tag)
	}
	SetTags([]string{"pprof", tag})
	if !TagNamed(tag) {
		t.Fatalf("TagNamed(%q) with the tag listed = false, want true", tag)
	}
	SetTags(nil)
	SetEnabled(true)
	if TagNamed(tag) {
		t.Fatalf("TagNamed(%q) under the global toggle = true, want false", tag)
	}
}
