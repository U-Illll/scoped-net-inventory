# DISCLAIMER — Research and Educational Use Only

The `c2/` module in this repository (the `c2server` and `c2implant` commands and
the packages they import) is a **research and teaching instrument for studying
command-and-control tasking protocol design**. It is published so that its
design and its guard rails can be read, criticised and reproduced in a
controlled environment.

## Scope of intended use

Permitted, in the spirit of this notice:

- Running both ends inside containers, VMs or a private lab network that **you
  own and control**, with no route to any third-party system.
- Reading the source to study tasking, enrolment, signing, result handling and
  failure modes.
- Adapting it in your own fork for defensive work: writing detections, testing
  whether your monitoring notices a beaconing pattern, or teaching protocol
  design.

## Prohibited

This software is **not** to be used to access, control, or interfere with any
system you do not own or lack explicit written authorisation to test. That
includes deploying an implant on a third party's machine, using this code for
persistence, credential theft, data exfiltration, lateral movement, or any
activity that is unlawful in your jurisdiction. You are solely responsible for
complying with the law and with the acceptable-use policy of any network or
host you touch.

## Guard rails built into the code

These are deliberate design limits, not features that can be toggled off:

| Guard rail | Where | Behaviour |
|---|---|---|
| Lab acknowledgement | `cmd/c2server`, `cmd/c2implant` | Both refuse to start without `-lab`. |
| Mandatory shared secret | `c2/server`, `c2/implant` | A secret shorter than 16 bytes is rejected at construction. |
| Signed traffic | `c2/proto` | Every request carries an HMAC-SHA256 over body + timestamp; unsigned or replayed requests get `401`. |
| Task-kind allowlist | `c2/proto.IsKnownKind` | Only `ping`, `sysinfo`, `scan`, `sleep`, `exit`, `exec` are accepted; anything else is refused at the server *and* again at the implant. |
| No shell for `exec` | `c2/implant.execAllowlisted` | Runs an absolute-path binary from an explicit argv, with no shell and no interpolation, and only if the path is in `-exec-allow`. |
| Scan scope is a hard gate | `c2/implant.scan` | Reuses the repository's `scope` package; an implant cannot be tasked to scan a host outside its own scope file. |
| No persistence or self-update | (absent by design) | There is no install routine, no watchdog, no auto-upgrade path. |
| No disk state on the server | `c2/server` | Queues, implants and results live in memory only; restarting clears everything. |

## No warranty

Provided **as is**, without warranty of any kind. The authors and contributors
accept no liability for damage, legal consequence, or loss arising from use of
this code. If you are unsure whether a use is lawful or authorised, do not run
it.

## Reporting

If you believe this repository contains something that should not be published,
open an issue describing the concern rather than using it.
