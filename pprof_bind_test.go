//go:build !js

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package argus

import (
	"net"
	"testing"
)

// The pprof server binds one named address, never every interface: an empty or unspecified host
// would serve the process's goroutines, heap and argv to any network the host is on.
func TestPprofBindsNoWildcardAddress(t *testing.T) {
	host, port, err := net.SplitHostPort(pprofAddr)
	if err != nil {
		t.Fatalf("pprof address %q: %v", pprofAddr, err)
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		t.Fatalf("pprof binds %q: host %q listens on every interface", pprofAddr, host)
	}
	if port != "6060" {
		t.Fatalf("pprof binds %q, want port 6060", pprofAddr)
	}
}
