# argus

argus gives Go services runtime diagnostics, switched by one `DEBUG` environment variable that holds a list of tags.

- **Debug loggers** per namespace. A logger whose namespace is off costs one atomic load.
- **Debug features** that register themselves from `init()` and start together on one `Start()` call. The built-in `pprof` feature serves only the pprof handlers on port 6060 of the host's private address (`FLY_PRIVATE_IP`, when it names a private IP), else of loopback; it never listens on every interface.
- **Tag gates**: `TagEnabled` follows the wildcards; `TagNamed` opens only for the exact tag, for surfaces that must stay shut under `DEBUG=*`.
- **`argus/audit`**: structured security-decision logs (deny, allow, challenge) over the default `slog` handler, with a fixed key vocabulary.
- **`argus/eventlog`**: a persistent audit-event sink. It encrypts the IP address and details through an `Encryptor` you supply and writes through an `EventStore` you supply; an empty partition is refused.

Standard library only.

## Use

```sh
go get github.com/bbmumford/argus
```

`DEBUG` takes tags separated by commas or spaces. `*` opens everything, `area.*` opens every tag under `area.`, and an exact tag opens that one. Matching is case-sensitive.

```go
import "github.com/bbmumford/argus"

var log = argus.New("mesh.dial")

func dial(addr string) {
	defer log.Trace("dial")()
	log.Printf("dialing %s", addr)
}

func main() {
	argus.Start() // starts every registered feature DEBUG opens, e.g. DEBUG=pprof
	// ...
}
```

A new debug feature is a file with an `init()` that calls `argus.Register(argus.Feature{Tag: "...", Desc: "...", Start: func() { ... }})`; `Start` must not block. `SetTags` replaces the tag list at run time, and `Configure`/`SetEnabled` switch every namespace on or off.

```go
deny := audit.New("auth")
deny.SecurityDeny(ctx, "token refused", "expired", subject, err)

events, err := eventlog.NewEventLogger(store, encryptor, nil)
err = events.LogEvent(ctx, partition, app, "login", "signed in", subject, ip, userAgent, details)
```

## Dependencies

None: argus uses only the standard library.

## Used by

Importers in the ORBTR estate:

- `github.com/ORBTR/Library/endpoint` (the endpoint spine calls `Start()`), and
  `audit` in `github.com/ORBTR/Library/agent`, `component/ipc`,
  `component/keyprotect`, `component/serviceunit`, `component/tlspin`,
  `mesh/wire`, `plugins`, `selfupdate`, `trustchain/custody` and more.
- `github.com/ORBTR/constellation/domain/foundation/notification` (root) and
  `domain/identity/provisioning/store`,
  `domain/networking/remote_access/signaling` (`audit`).
- `github.com/ORBTR/agent/systempart` and `systempart/wire` (`audit`).
- `github.com/ORBTR/relay.orbtr.io` (root and `audit`),
  `github.com/ORBTR/node.orbtr.io` (`audit`) and, in its tests,
  `github.com/ORBTR/help.orbtr.io`.
- `github.com/bbmumford/flyio`.

## Platforms and build

Pure Go, no cgo. The `pprof` feature (`pprof.go`) builds everywhere but js;
the rest of the module builds everywhere. The module's `go` directive is
1.25.0.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code.
