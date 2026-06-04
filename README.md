# dsmr-localfirst

System-first recipient routing for hybrid system/vpopmail mail domains in the
DSMR qmail stack.

## Problem

On a domain that vpopmail owns, qmail-smtpd's `chkuser` validates every
recipient against vpopmail only. An address meant for a *system* user (a shell
account) is rejected `550 ... nomailbox` at SMTP time even though qmail-send
would deliver it correctly. The same domain cannot cleanly serve both shell
users and vpopmail virtual users.

## Design

> Hybrid domains resolve system users first, then fall through to vpopmail.

Resolution is dynamic — adding a normal Unix account is sufficient for that user
to receive mail, with no per-user alias or assign to provision. A single
eligibility predicate is shared by every component so the SMTP-time and
delivery-time paths can never disagree.

A local-part `L` is a **mail-eligible system identity** iff either `getent
passwd L` resolves to an account whose home is under `/home/`, or
`~alias/.qmail-L` exists. Otherwise resolution falls through to vpopmail.

## Components

| Program | Role |
|---------|------|
| `system-identity` (`/usr/sbin`) | CLI for the shared eligibility predicate; the canonical probe for debugging routing. |
| `localfirst-rcptcheck` (`/var/qmail/bin`) | qmail-smtpd `RCPTCHECK` validator replacing `chkuser`. |
| `localfirst-dispatch` (`/var/qmail/bin`) | delivery-time `.qmail-default` replacement; re-injects system recipients, otherwise runs `vdelivermail`. |

The validator shells out to vpopmail's `vrcptcheck` for the vpopmail-existence
check (backend-agnostic, so it works against vpopmail's SQL backends), and links
no vpopmail code itself. On a host with no vpopmail at all, the validator is a
pure system-identity gate.

## Configuration

- `control/localfirstdomains` — domains where system-first applies (see
  `examples/localfirstdomains`). Each must also be in `control/rcpthosts`.
- Wiring of `RCPTCHECK` and the `.qmail-default` dispatcher is performed by
  `dsmr-qmail-run` (>= 1.0-10) and the deploying administrator.

## Operational notes

- During a vpopmail SQL backend outage the validator **defers** affected
  recipients (`451`) and logs `LOG_CRIT` to the mail facility — it never
  permanently rejects, and it never injects alert mail into a degraded MTA.
  Alert on the log out-of-band.
- Set `control/maxrcpt` to bound recipients per session; this package does not
  reimpose `chkuser`'s recipient-count limit.
