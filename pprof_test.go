//go:build !js

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package argus

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// pprofBindAddr answers the private address FLY_PRIVATE_IP names and loopback for anything else.
func TestPprofBindAddrIsPrivateOrLoopback(t *testing.T) {
	for env, want := range map[string]string{
		"":                "127.0.0.1:6060",
		"fdaa:0:1:a7b::3": "[fdaa:0:1:a7b::3]:6060",
		" fdaa::2 ":       "[fdaa::2]:6060",
		"10.0.0.5":        "10.0.0.5:6060",
		"::":              "127.0.0.1:6060",
		"0.0.0.0":         "127.0.0.1:6060",
		"8.8.8.8":         "127.0.0.1:6060",
		"2001:db8::1":     "127.0.0.1:6060",
		"not-an-ip":       "127.0.0.1:6060",
	} {
		got := pprofBindAddr(func(k string) string {
			if k == "FLY_PRIVATE_IP" {
				return env
			}
			return ""
		})
		if got != want {
			t.Errorf("FLY_PRIVATE_IP=%q: pprof binds %q, want %q", env, got, want)
		}
	}
}

// startPprof listens on pprofAddr and serves the pprof handlers alone: a handler registered on
// http.DefaultServeMux is not reachable through it.
func TestStartPprofServesOnlyPprofOnItsAddress(t *testing.T) {
	const defaultOnly = "/argus-test-default-mux-only"
	http.HandleFunc(defaultOnly, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "default mux") })

	var asked string
	served := make(chan net.Listener, 1)
	orig := pprofListen
	t.Cleanup(func() { pprofListen = orig })
	pprofListen = func(network, addr string) (net.Listener, error) {
		asked = addr
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err == nil {
			served <- ln
		}
		return ln, err
	}
	startPprof()
	if asked != pprofAddr {
		t.Fatalf("startPprof listened on %q, want pprofAddr %q", asked, pprofAddr)
	}
	ln := <-served
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Errorf("ln.Close: %v", err)
		}
	})

	client := &http.Client{Timeout: 5 * time.Second}
	get := func(path string) int {
		resp, err := client.Get("http://" + ln.Addr().String() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		if err := resp.Body.Close(); err != nil {
			t.Errorf("resp.Body.Close: %v", err)
		}
		return resp.StatusCode
	}
	if code := get("/debug/pprof/"); code != http.StatusOK {
		t.Fatalf("GET /debug/pprof/ = %d, want 200", code)
	}
	if code := get("/debug/pprof/cmdline"); code != http.StatusOK {
		t.Fatalf("GET /debug/pprof/cmdline = %d, want 200", code)
	}
	if code := get(defaultOnly); code != http.StatusNotFound {
		t.Fatalf("GET %s through the pprof server = %d, want 404: the default mux is served", defaultOnly, code)
	}
}
