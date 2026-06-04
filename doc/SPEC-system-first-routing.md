# SPEC — System-first recipient routing (hybrid system/vpopmail domains)

Status: ACCEPTED — decisions resolved (see §12), ready for implementation
Target host (first deployment): b612.asteroid.radio
Motivation: shipping gap — mail to shell-user addresses on a vpopmail virtual
domain is rejected at SMTP time by chkuser.

## 1. Problem

On a domain that vpopmail "owns" (present in `virtualdomains` → vpopmail, with a
`+domain-:` catch-all assign), `qmail-smtpd`'s chkuser validates every recipient
against **vpopmail only**. It never consults `users/assign` or the system
password database, so an address that is meant to be delivered to a *system*
user (shell account) is rejected `550 ... nomailbox (chkuser)` even though
`qmail-send` would deliver it correctly.

The current production state on b612 papers over this with per-user vpopmail
aliases that shadow `=domain-user:` qmail assigns — two representations of one
fact, hand-maintained, easy to drift. This spec replaces that with a single
dynamic mechanism.

## 2. Design principle

> **Hybrid domains resolve system users first, then fall through to vpopmail.**

Recipient resolution must be **dynamic** (look the identity up at run time), not
**static** (a per-user routing entry that has to be provisioned and migrated).
Adding a normal Unix account must be sufficient for that user to receive mail —
no separate mail-provisioning step, no per-user assign, no per-user alias.

## 3. Eligibility contract (the shared rule)

A local-part `L` on a hybrid domain is a **mail-eligible system identity** iff
either:

1. `getent passwd L` resolves to an account whose home directory is under
   `/home/` (a real human/shell account), **or**
2. `~alias/.qmail-L` exists (an alias-configured system identity, e.g.
   `~alias/.qmail-root`, `~alias/.qmail-postmaster`).

Otherwise `L` is not a system identity and resolution falls through to vpopmail.

This single predicate is used by BOTH the delivery dispatcher and the SMTP-time
validator. It MUST have exactly one implementation (a shared helper) so the two
paths can never disagree.

Security note: clause 1 is scoped to homes under `/home/` precisely to exclude
service accounts (`bin`, `daemon`, `www-data`, …) whose homes are elsewhere.
`alias`'s own home is `/var/lib/qmail/alias`, so it is reached only via clause 2.

## 4. Architecture

Three pieces, one shared rule:

### 4.1 Shared eligibility helper
A small program/script `system-identity` that, given a local-part, exits 0 and
prints the delivery target if eligible (per §3), non-zero otherwise. Single
source of truth for both components below.

### 4.2 Delivery dispatcher  (delivery time)
Replaces the hybrid vpopmail domain's `.qmail-default`
(currently `| /home/vpopmail/bin/vdelivermail '' delete`) with a program:

```
local-part = $DEFAULT (or $EXT) from qmail
if system-identity local-part:
    deliver to that system identity   # forward to <local-part>@<host-local-domain>
else:
    exec /home/vpopmail/bin/vdelivermail '' delete   # unchanged vpopmail path
```

Delivery to the system identity is done by **re-injecting** to
`<local-part>@b612.asteroid.radio` (the `locals` host domain) rather than
writing the Maildir directly, because the catch-all runs as the vpopmail user
and must not write into a user-owned `~/Maildir`. Re-injection lets qmail
deliver with correct ownership via `control/defaultdelivery`.

Result: no per-user `=domain-user:` assigns required. A new `/home` account is
delivered to automatically.

### 4.3 SMTP-time validator  (RCPTCHECK)
A program wired via `RCPTCHECK` (qmail-smtpd.c already supports it). Logic per
RCPT:

```
if recipient domain NOT in rcpthosts:
    accept            # relay target — permission already enforced by AUTH+tcprules
elif domain in localfirstdomains:
    accept if  system-identity local-part     # system-first
           or  vpopmail user/alias exists      # fallthrough (chkuser-equivalent)
    reject otherwise   (550 5.1.1)
else:                  # local rcpthosts domain, non-hybrid
    accept if  vpopmail user/alias exists      # pure vpopmail (chkuser-equivalent)
    reject otherwise
```

**Relay safety (critical):** the validator must NEVER reject a recipient whose
domain is not a local `rcpthosts` domain — otherwise authenticated submission to
external addresses (`friend@gmail.com`) would be rejected. Relay *permission* is
enforced before RCPTCHECK by AUTH + tcprules (an unauthenticated client cannot
present an external recipient; an authenticated/relayclient one is entitled to
relay anywhere). Note `qmail-smtpd.c:1563` runs RCPTCHECK when
`!relayclient || rcptcheckrelayclient`; submission sets `RCPTCHECKRELAYCLIENT=1`,
so the validator DOES run for authenticated submitters — hence the explicit
"domain not in rcpthosts → accept" first clause is load-bearing, not cosmetic.

chkuser is turned OFF (`CHKUSER_START` unset) so the validator is the sole
recipient gate. The validator's vpopmail branch reproduces chkuser's
recipient-existence check; see §6 for what else chkuser did.

### 4.4 Domain scoping
System-first applies only to designated domains, via a new control file
`control/localfirstdomains` (one domain per line). For b612:

```
asteroid.radio
```

For any domain NOT listed, the validator and dispatcher skip the system-first
branch and behave as pure vpopmail (chkuser-equivalent). This keeps the feature
safe on multi-domain hosts (otherwise `fade@anydomain` would be accepted just
because `fade` is a system user).

## 5. Configuration changes (b612)

- `control/defaultdelivery` = `./Maildir/`  (currently ABSENT — latent bug;
  required so re-injected system delivery lands in `~/Maildir`, Maildir format).
- `control/localfirstdomains` = `asteroid.radio` (new).
- vpopmail domain `.qmail-default` → the dispatcher (§4.2).
- `qmail-smtpd/run` and `qmail-submission/run`: stop exporting
  `CHKUSER_START=ALWAYS`; export `RCPTCHECK=<validator>` (+ keep
  `RCPTCHECKRELAYCLIENT` semantics — relayclients/authenticated submission
  bypass recipient validation, which is correct).
- Revert the five stop-gap vpopmail aliases (fade/glenneth/luis/asteroid/root)
  — the dispatcher makes them unnecessary.

## 6. chkuser disposition (decision needed)

Disabling chkuser drops more than recipient-existence. chkuser also did:
sender domain MX/format checks, recipient-count-per-session limit, mailbox-full
(quota) rejection, rcpt/sender syntax checks. Options:

- **(A) Validator-only (chosen approach "a").** Accept the loss of chkuser's
  sender-side and limit checks; the RCPTCHECK validator enforces recipient
  existence (the security-relevant one). Simplest. Recipient-count limit can be
  added to the validator cheaply if wanted; sender-MX is the main thing lost.
- **(B) Patch chkuser instead.** Add the §3 system-identity check into
  `chkuser_realrcpt()` so chkuser accepts system users natively and ALL its
  other checks stay. No RCPTCHECK needed. Cost: a C patch to dsmr-qmail +
  qmail rebuild/redeploy; ties the feature into the qmail package.

This spec is written for (A) per the chosen direction; (B) is recorded as the
alternative if the lost chkuser checks turn out to matter.

## 7. Packaging (decision needed)

The feature spans validation wiring (run scripts, owned by **dsmr-qmail-run**),
delivery (`.qmail-default` dispatcher), a shared eligibility helper, and the
new control file. Options:

- **New package `dsmr-localfirst`** — owns `system-identity`, the dispatcher,
  the RCPTCHECK validator, and ships/documents the control files. `dsmr-qmail-run`
  gains a dependency and its run scripts wire `RCPTCHECK` to the validator.
  Cleanest separation, independent lifecycle; cost is a new repo + the
  cross-package run-script wiring. Fits the stack's one-concern-per-package rule.
- **Fold into `dsmr-qmail-run`** — it already owns the run scripts that wire
  `RCPTCHECK` (presence-based: `if [ -x .../rcptcheck-overlimit ]`), so the
  validator/dispatcher/helper live beside the thing that activates them. Fastest
  to ship (no new repo), but widens dsmr-qmail-run from "run scripts" to
  "runtime recipient policy."

**RESOLVED: new package `dsmr-localfirst`.** It owns `system-identity`, the
dispatcher, the RCPTCHECK validator, and ships/documents the control files.
`dsmr-qmail-run` gains a dependency on it and its run scripts wire `RCPTCHECK`
to the validator. This keeps the clean one-concern-per-package boundary the
rest of the stack follows.

## 8. Provisioning & migration

- **Provisioning:** none per-user. Creating a `/home` account (or an
  `~alias/.qmail-L`) is the whole story. A `~/Maildir` is laid down from the
  `/etc/skel` template at account-creation time (the normal path). As a
  safety net, the delivery dispatcher creates `~/Maildir` (owned by the target
  user, Maildir layout) if it is somehow absent at delivery time, so a message
  is never lost to a missing mailbox.
- **Migration of legacy accounts:** existing `/home` accounts and existing
  `~alias/.qmail-*` light up the moment the dispatcher + validator are in place —
  no per-user migration. Sweep step: ensure each eligible account has `~/Maildir`.
- **Decommissioning the stop-gap:** remove the 5 vpopmail aliases and the
  per-user `=asteroid.radio-<user>:` assigns (delivery now flows through the
  dispatcher). Rebuild `users/cdb` after assign changes.

## 9. Rollback

Each change is independently reversible:
- restore `.qmail-default` to `vdelivermail '' delete`;
- re-export `CHKUSER_START=ALWAYS`, unset `RCPTCHECK`;
- re-add the per-user aliases if needed.
Keep timestamped backups of every edited control/run file.

## 10. Test plan

From outrider (non-relay path), SMTP RCPT probe (no DATA):
- `fade@asteroid.radio` → 250 (system, /home)
- `root@asteroid.radio` → 250 (alias clause)
- `<real-vpopmail-user>@asteroid.radio` → 250 (fallthrough)
- `nonexistent@asteroid.radio` → 550 (neither)
- `bin@asteroid.radio` → 550 (system acct but home not under /home → not eligible)
Then end-to-end: deliver a message to `fade@asteroid.radio` and confirm it lands
in `/home/fade/Maildir/new`; deliver to a vpopmail user and confirm vpopmail
delivery; confirm a relayclient/authenticated submission still bypasses the
validator.

## 12. Resolved decisions

- **Packaging:** new package `dsmr-localfirst` (§7).
- **chkuser:** validator-only, approach (A) (§6). Recipient-count limit is NOT
  reimplemented for the initial ship; it can be added to the validator later if
  the loss matters.
- **Language:** C program for `system-identity`, the dispatcher, and the
  RCPTCHECK validator. Rationale: the system will ultimately be deployed in
  scenarios where system-level delivery for the default domain is the *only*
  configuration, so the recipient path must be fast and self-contained (no
  per-RCPT `getent` fork). The three programs share one C implementation of the
  §3 eligibility predicate so the delivery and validation paths can never
  disagree.
- **`~/Maildir` creation:** laid down from `/etc/skel` at account-creation
  (normal path); delivery dispatcher creates it as a fallback if absent (§8).
