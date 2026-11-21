# argus

Runtime diagnostics for Go services, switched by one `DEBUG` environment variable that holds a list of tags.

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

## Consumers

ORBTR library (the endpoint spine calls `Start()`), io constellation, agent, tools and the node, relay and help endpoints, ai xyz, and the flyio package.
