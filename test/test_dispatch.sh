#!/bin/bash
# Decision test for localfirst-dispatch. Compiled with forward/vdelivermail/
# control-me paths pointed at stubs that print which delivery path was taken,
# so we can assert the dispatcher routes correctly without a live qmail.
# system_identity runs against the live passwd db (a real /home account is the
# system-identity case).
set -u
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0
pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; fails=$((fails + 1)); }

cat > "$tmp/forward" <<'EOF'
#!/bin/bash
printf 'FORWARD %s\n' "$1"
EOF
cat > "$tmp/vdelivermail" <<'EOF'
#!/bin/bash
printf 'VDELIVERMAIL [%s] [%s]\n' "$1" "$2"
EOF
chmod +x "$tmp/forward" "$tmp/vdelivermail"
printf 'b612.asteroid.radio\n' > "$tmp/me"

"${CC:-cc}" ${CFLAGS:--O2 -Wall -Wextra} \
    -DFORWARD="\"$tmp/forward\"" \
    -DVDELIVERMAIL="\"$tmp/vdelivermail\"" \
    -DCONTROL_ME="\"$tmp/me\"" \
    -o "$tmp/dispatch-t" src/localfirst-dispatch.c src/system_identity.c || {
        fail "compile dispatch under test"; exit 1; }

home_user=$(getent passwd | awk -F: '$6 ~ /^\/home\// {print $1; exit}')

# expect_out DESC WANT_SUBSTR  -- runs with env/args set by caller via globals
run() { # run DEFAULT EXT HOSTARG
    local d=$1 e=$2 h=$3
    env -u DEFAULT -u EXT \
        ${d:+DEFAULT="$d"} ${e:+EXT="$e"} \
        "$tmp/dispatch-t" ${h:+"$h"} 2>/dev/null
}

check() { # check DESC WANT_SUBSTR ACTUAL
    if printf '%s' "$3" | grep -qF -- "$2"; then pass "$1"
    else fail "$1 (got: '$3', want substr: '$2')"; fi
}

if [ -n "$home_user" ]; then
    out=$(run "$home_user" "" "b612.asteroid.radio")
    check "system user re-injected via forward" "FORWARD $home_user@b612.asteroid.radio" "$out"
fi

out=$(run "ghostuser-xyz" "" "b612.asteroid.radio")
check "unknown user -> vdelivermail '' delete" "VDELIVERMAIL [] [delete]" "$out"

# HOST from control/me when no argv
if [ -n "$home_user" ]; then
    out=$(run "$home_user" "" "")
    check "host falls back to control/me" "FORWARD $home_user@b612.asteroid.radio" "$out"
fi

# EXT used when DEFAULT empty
if [ -n "$home_user" ]; then
    out=$(run "" "$home_user" "b612.asteroid.radio")
    check "EXT used when DEFAULT empty" "FORWARD $home_user@b612.asteroid.radio" "$out"
fi

# neither DEFAULT nor EXT -> temp failure (exit 111), no delivery
env -u DEFAULT -u EXT "$tmp/dispatch-t" "b612.asteroid.radio" >/dev/null 2>&1
if [ $? -eq 111 ]; then pass "no DEFAULT/EXT -> temp failure (exit 111)"
else fail "no DEFAULT/EXT should exit 111"; fi

if [ "$fails" -ne 0 ]; then printf '%d failure(s)\n' "$fails"; exit 1; fi
printf 'all dispatch decision tests passed\n'
