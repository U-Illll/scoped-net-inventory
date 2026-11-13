# scoped-net-inventory

A small TCP reachability inventory that **refuses to run without a written
scope**. It answers one question — "which of my authorised hosts accept a TCP
connection on these ports?" — and nothing else.

This exists as a safe, containerised alternative to running a general-purpose
scanner against a network: the authorisation file is a hard gate, not a
suggestion.

## What it does not do

- No scope → no scan. There is no `--all`, no `0.0.0.0/0` shortcut, no
  "ignore scope" flag.
- No payloads, no banners, no protocol negotiation, no authentication attempts.
  A successful connection is recorded and closed immediately.
- No fingerprinted or spoofed traffic, no evasion, no challenge handling.
- No remote control channel, no tasking, no persistence. It runs, writes a JSON
  file, and exits.

## Scope file

```json
{
  "networks": ["192.0.2.0/28"],
  "hosts": ["db.internal", "cache.internal"],
  "ports": [22, 80, 443, 5432],
  "note": "ticket OPS-1234, owner confirmed 2026-01-01"
}
```

Rules enforced at load time:

- An empty scope is an error (fail closed).
- Unknown keys are rejected so a typo cannot silently drop an authorisation.
- Every target is re-checked against the scope before a socket is opened.
- `-expand` enumerates CIDR members only up to `-max-hosts` (default 256) and
  refuses larger prefixes instead of truncating them.

## Usage

```bash
go build -o netinv ./cmd/netinv

./netinv -scope examples/scope.demo.json -out report.json
./netinv -scope my-scope.json -print-scope      # inspect the compiled scope
```

Flags: `-timeout` (per connection, default 1500ms), `-concurrency`
(default 8, hard cap 32), `-max-hosts` (default 256), `-expand`.

## Report

```json
{
  "generated_at": "2026-01-01T00:00:00Z",
  "scope": {"networks": [], "hosts": ["mock-asset"], "ports": [8080, 8081], "source": "scope.json"},
  "hosts_scanned": 1,
  "ports_scanned": 2,
  "open_count": 1,
  "elapsed_ms": 2,
  "results": [
    {"host": "mock-asset", "port": 8080, "open": true, "ms": 1},
    {"host": "mock-asset", "port": 8081, "open": false, "ms": 1}
  ]
}
```

## Docker demo

The compose stack builds one image from this repository and runs it twice: a
throwaway `mock-asset` HTTP service on port 8080, and the inventory itself
scanning it. Both sit on an `internal: true` network, which means Docker gives
that network no route off-host — the demonstration scan physically cannot reach
anything but the mock container.

The demo scope lists ports 8080 and 8081, so the report contains one open and
one closed observation.

```bash
mkdir -p out
docker compose up --build          # mock-asset starts, inventory scans, writes out/report.json
cat out/report.json
docker compose down
```

Because the image is built locally, the demo pulls nothing beyond the official
`alpine:3.20` and `golang:1.22-alpine` bases.

Swap `examples/scope.demo.json` for your own scope file and the `mock-asset`
service for real endpoints; nothing else needs to change.

## Tests

```bash
go test ./...
```

The suite covers fail-closed behaviour on empty/invalid scopes, out-of-scope
refusal, the host-count cap, and an open/closed port pair against a local
listener.

## License

MIT.
