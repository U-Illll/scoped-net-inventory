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

## Lab C2 module (`c2/`)

> **Research and educational use only.** Read [DISCLAIMER.md](DISCLAIMER.md)
> before running anything in this section. Both binaries refuse to start without
> `-lab`, which is your explicit acknowledgement of that document.

`c2/` is a small command-and-control pair for studying tasking protocol design:
a server, an implant, and a signed JSON wire format between them. It exists so
the scan task from the inventory above can be driven remotely, and so the
enrolment/tasking/result path can be read and criticised.

```bash
docker compose --profile c2 up -d c2-server c2-implant mock-asset
docker compose --profile c2 exec c2-server sh -c \
  'wget -qO- --header="X-Operator-Token: lab-operator-token" \
   http://127.0.0.1:8443/operator/implants'
```

Queueing a scan task through the operator API:

```bash
curl -s -X POST http://127.0.0.1:8443/operator/task \
  -H 'X-Operator-Token: lab-operator-token' \
  -H 'Content-Type: application/json' \
  -d '{"implant_id":"lab-implant-1","kind":"scan","args":{"hosts":"mock-asset"}}'
```

The implant then reports something like:

```
mock-asset:8080 open=true ms=0
mock-asset:8081 open=false ms=0
total_hosts=1 open=1
```

### What it deliberately does not do

| Guard rail | Effect |
|---|---|
| `-lab` required | `c2server`/`c2implant` exit 2 without it. |
| Shared secret ≥ 16 bytes | Rejected at construction, not at runtime. |
| HMAC + timestamp on every request | Unsigned, tampered or replayed requests get `401`. |
| Task-kind allowlist | Only `ping`, `sysinfo`, `scan`, `sleep`, `exit`, `exec`. `shell`, `persist`, `download` etc. are rejected at the server **and** again at the implant. |
| No shell for `exec` | Absolute-path binary from an explicit argv, no interpolation, and only if listed in `-exec-allow`. Asking for `/bin/sh` is refused. |
| Scan scope is a hard gate | The implant reuses `scope`; tasking `192.0.2.1` when the scope file only authorises `127.0.0.1` returns `refusing out-of-scope host`. |
| No persistence / no self-update | There is no install routine, watchdog or upgrade path in the code. |
| Server is memory-only | Restart clears implants, queues and results. |

Both ends run on an `internal: true` Docker network, so the lab pair has no
route to the host or the internet.

## Tests

```bash
go test ./...
```

The suite covers fail-closed behaviour on empty/invalid scopes, out-of-scope
refusal, the host-count cap, an open/closed port pair against a local listener,
plus the C2 guard rails: signature and replay rejection, the task-kind
allowlist on both sides, exec allowlist enforcement, and the one-time task
delivery cap.

## License

MIT.
