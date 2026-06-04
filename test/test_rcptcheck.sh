#!/bin/bash
# Decision-tree test for localfirst-rcptcheck. Control-file, vrcptcheck,
# SQL-config, and chain paths are pointed at fixtures so the full disposition
# matrix can be driven without a live qmail/vpopmail. The vpopmail check is
# served by a stub vrcptcheck (exists if local-part starts with "real",
# temp if "tmp", absent otherwise). system_identity runs against the live
# passwd db, so a real /home account is the system-first case.
set -u
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0
pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; fails=$((fails + 1)); }

# --- fixtures ---
# rcpthosts includes a leading-dot wildcard entry to exercise suffix matching.
printf 'asteroid.radio\nmail.example.com\n.wild.example\n' > "$tmp/rcpthosts"
printf 'asteroid.radio\n'                                  > "$tmp/localfirstdomains"

cat > "$tmp/vrcptcheck" <<'EOF'
#!/bin/bash
addr=$(cat <&3)
local=${addr%%@*}
case "$local" in
  real*) exit 0 ;;
  tmp*)  exit 111 ;;
  *)     exit 1 ;;
esac
EOF
chmod +x "$tmp/vrcptcheck"

cflags="${CFLAGS:--O2 -Wall -Wextra}"
defs=(
  -DRCPTHOSTS="\"$tmp/rcpthosts\""
  -DLOCALFIRSTDOMAINS="\"$tmp/localfirstdomains\""
  -DVRCPTCHECK="\"$tmp/vrcptcheck\""
  -DVPOPMAIL_SQLCONF="\"$tmp/sqlconf\""     # created only for the down-test
  -DRCPTCHECK_CHAIN="\"$tmp/chain\""        # created only for the chain-test
  -DBACKEND_PROBE_TIMEOUT=2
)
# Primary binary: vrcptcheck present.
"${CC:-cc}" $cflags "${defs[@]}" \
    -o "$tmp/rc" src/localfirst-rcptcheck.c src/system_identity.c \
    || { fail "compile validator"; exit 1; }
# System-only binary: vrcptcheck path does not exist (no vpopmail layer).
"${CC:-cc}" $cflags \
    -DRCPTHOSTS="\"$tmp/rcpthosts\"" -DLOCALFIRSTDOMAINS="\"$tmp/localfirstdomains\"" \
    -DVRCPTCHECK="\"$tmp/NO-vrcptcheck\"" -DVPOPMAIL_SQLCONF="\"$tmp/sqlconf\"" \
    -DRCPTCHECK_CHAIN="\"$tmp/chain\"" \
    -o "$tmp/rc_nolayer" src/localfirst-rcptcheck.c src/system_identity.c \
    || { fail "compile system-only validator"; exit 1; }

home_user=$(getent passwd | awk -F: '$6 ~ /^\/home\// {print $1; exit}')

expect() { # expect DESC WANT [RECIPIENT]  (uses $BIN, default $tmp/rc)
    local desc=$1 want=$2 got bin=${BIN:-$tmp/rc}
    if [ "$#" -ge 3 ]; then RECIPIENT="$3" "$bin"; got=$?
    else unset RECIPIENT; "$bin"; got=$?; fi
    if [ "$got" -eq "$want" ]; then pass "$desc (exit $got)"
    else fail "$desc (exit $got, want $want)"; fi
}

# Ensure the optional fixtures are absent for the baseline cases.
rm -f "$tmp/sqlconf" "$tmp/chain"

# --- baseline disposition matrix ---
expect "external relay target accepted"        0   "friend@gmail.com"
if [ -n "$home_user" ]; then
    expect "hybrid + system user accepted"      0   "$home_user@asteroid.radio"
    expect "hybrid + mixed-case system user accepted" 0 "${home_user^}@asteroid.radio"
fi
expect "hybrid fallthrough to vpopmail exists"  0   "realbob@asteroid.radio"
expect "hybrid unknown rejected"                100 "ghost@asteroid.radio"
expect "hybrid service-acct not system-first"   100 "bin@asteroid.radio"
expect "pure vpopmail exists accepted"          0   "realbob@mail.example.com"
expect "pure vpopmail unknown rejected"         100 "ghost@mail.example.com"
expect "vpopmail temp failure deferred"         111 "tmpguy@mail.example.com"
expect "embedded-@ local on local domain rejected" 100 "a@b@asteroid.radio"
expect "embedded-@ local on relay target accepted"   0 "a@b@gmail.com"
expect "malformed recipient accepted"           0   "noatsign"
expect "missing RECIPIENT deferred"             111

# --- E: leading-dot wildcard matching ---
expect "wildcard subdomain treated as local (unknown->reject)" 100 "ghost@sub.wild.example"
expect "wildcard subdomain exists accepted"     0   "realbob@deep.sub.wild.example"
expect "lookalike domain NOT matched (relay accept)" 0 "ghost@evilwild.example"

# --- D: backend-down -> defer (not reject) ---
# vrcptcheck returns absent (exit 1); the SQL config points at a refused port,
# so the liveness probe must map the absent result to a temp failure.
printf '127.0.0.1|1|u|p|db\n' > "$tmp/sqlconf"
expect "backend down -> deferred not rejected"  111 "ghost@mail.example.com"
rm -f "$tmp/sqlconf"

# --- A: chaining to the next RCPTCHECK program on accept ---
# An installed chain program must run on the accept path and own the verdict.
cat > "$tmp/chain" <<'EOF'
#!/bin/bash
exit 42
EOF
chmod +x "$tmp/chain"
expect "accept hands off to chain program"      42  "realbob@asteroid.radio"
rm -f "$tmp/chain"

# --- C: system-only host (vrcptcheck not installed) -> unknown rejected ---
BIN="$tmp/rc_nolayer" expect "system-only: unknown local recipient rejected" 100 "ghost@mail.example.com"
if [ -n "$home_user" ]; then
    BIN="$tmp/rc_nolayer" expect "system-only: system identity still accepted" 0 "$home_user@asteroid.radio"
fi

if [ "$fails" -ne 0 ]; then printf '%d failure(s)\n' "$fails"; exit 1; fi
printf 'all rcptcheck decision tests passed\n'
