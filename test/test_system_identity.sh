#!/bin/bash
# Behavioural test for the system-identity CLI against the live passwd database.
# Clause 1 (/home account) and the service-account / nonexistent negatives are
# checked here. Clause 2 (~alias/.qmail-L) needs a real qmail alias user and is
# exercised in the on-host integration test, not here.
set -u

cd "$(dirname "$0")/.."

fails=0
pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; fails=$((fails + 1)); }

# expect_exit DESC EXPECTED LOCALPART
expect_exit() {
    local desc=$1 want=$2 lp=$3 got
    ./system-identity "$lp" >/dev/null 2>&1
    got=$?
    if [ "$got" -eq "$want" ]; then
        pass "$desc ($lp -> exit $got)"
    else
        fail "$desc ($lp -> exit $got, want $want)"
    fi
}

# --- ext-translation unit test ---
"${CC:-cc}" ${CFLAGS:--O2 -Wall} -o test/test_ext test/test_ext.c src/system_identity.c \
    && ./test/test_ext || fail "ext translation unit test"

# --- qmail-local deliverability unit test (.qmail-<ext>/.qmail-...default chain) ---
"${CC:-cc}" ${CFLAGS:--O2 -Wall} -o test/test_deliverable test/test_deliverable.c src/system_identity.c \
    && ./test/test_deliverable || fail "qmail deliverability unit test"

# --- clause 1: a real /home account is eligible ---
# Pick a passwd entry whose home is under /home/ to keep the test host-agnostic.
home_user=$(getent passwd | awk -F: '$6 ~ /^\/home\// {print $1; exit}')
if [ -n "$home_user" ]; then
    expect_exit "clause 1 /home account eligible" 0 "$home_user"
    # qmail lowercases the local-part before delivery; a mixed-case recipient
    # must resolve to the same /home account.
    expect_exit "clause 1 mixed-case still eligible" 0 "${home_user^}"
else
    printf 'skip clause 1: no /home account on this host\n'
fi

# A local-part containing '@' cannot be a system account and must not match.
expect_exit "local-part with @ rejected" 1 "a@b"

# --- negative: a service account (home not under /home/) is NOT a system id ---
# 'bin' exists on every Debian host with home /bin or /usr/bin (not /home).
if getent passwd bin >/dev/null; then
    expect_exit "service account rejected" 1 bin
else
    printf 'skip service-account negative: no bin account\n'
fi

# --- negative: a name with no passwd entry and no alias falls through ---
expect_exit "nonexistent localpart falls through" 1 "no-such-user-xyzzy-42"

if [ "$fails" -ne 0 ]; then
    printf '%d failure(s)\n' "$fails"
    exit 1
fi
printf 'all system-identity tests passed\n'
