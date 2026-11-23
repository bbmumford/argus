//go:build !js

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package argus

import (
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
)

// pprofPort is the pprof server's port, the Go community convention.
const pprofPort = "6060"

// pprofAddr is the one address the pprof server binds, chosen once from the process environment by
// pprofBindAddr. The feature registration below names it, and startPprof listens on it.
var pprofAddr = pprofBindAddr(os.Getenv)

// pprofListen opens the pprof server's listener; net.Listen outside a test.
var pprofListen = net.Listen

// pprofBindAddr chooses the pprof server's address: the host's private network address when
// FLY_PRIVATE_IP names one (a Fly Machine's 6PN address, which `flyctl proxy 6060:6060 -a <app>`
// reaches over the organisation's WireGuard network), and loopback otherwise. An address that is
// unspecified, public or not an IP is never chosen, so the server never listens on every interface
// or a public one: a host with no private network address serves pprof to its own processes only.
// getenv is os.Getenv outside a test.
func pprofBindAddr(getenv func(string) string) string {
	if ip := net.ParseIP(strings.TrimSpace(getenv("FLY_PRIVATE_IP"))); ip != nil && ip.IsPrivate() {
		return net.JoinHostPort(ip.String(), pprofPort)
	}
	return net.JoinHostPort("127.0.0.1", pprofPort)
}

func init() {
	Register(Feature{
		Tag:   "pprof",
		Desc:  "Go pprof HTTP server on " + pprofAddr + " (the host's private network address, else loopback)",
		Start: startPprof,
	})
}

// pprofMux serves the pprof handlers alone. Importing net/http/pprof also registers them on
// http.DefaultServeMux; the pprof server serves this mux instead, so no handler another package
// put on the default mux is reachable on the pprof port.
func pprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// startPprof starts the Go pprof HTTP server on pprofAddr, serving pprofMux. It is the pprof
// feature's Start, which debug.Start() runs once when the DEBUG list holds "pprof" or "*". A
// listener that cannot open is logged and the server does not start.
//
// The server answers anyone who can reach pprofAddr, without authentication, for as long as the
// process runs: on a Fly Machine, any peer on the organisation's private network and a developer's
// `flyctl proxy`; elsewhere, only processes on the host. What it exposes:
//   - /debug/pprof/goroutine?debug=2 — full goroutine dump
//   - /debug/pprof/heap            — heap allocation profile
//   - /debug/pprof/profile         — 30 s CPU profile
//   - /debug/pprof/mutex           — contended mutexes
//   - /debug/pprof/threadcreate    — OS thread creation profile
//   - /debug/pprof/cmdline         — process argv (build args land here;
//     treat as semi-sensitive)
//
// Usage from a developer machine when a Fly endpoint is wedged:
//
//	flyctl proxy 6060:6060 -a <app>
//	curl http://localhost:6060/debug/pprof/goroutine?debug=2 > goroutines.txt
func startPprof() {
	ln, err := pprofListen("tcp", pprofAddr)
	if err != nil {
		log.Printf("[PPROF] not started on %s: %v", pprofAddr, err)
		return
	}
	log.Printf("[PPROF] serving on %s", ln.Addr())
	go func() {
		if err := http.Serve(ln, pprofMux()); err != nil {
			log.Printf("[PPROF] server exited: %v", err)
		}
	}()
}
