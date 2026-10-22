#!/usr/bin/env bash
#
# Multisite smoke test (issue #5): a super admin's scoped password must not be able to use
# super-admin powers, because is_super_admin() bypasses map_meta_cap.
#
# Usage: tests/multisite.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${APS_PORT:-9401}"
# Multisite refuses non-default ports, so WordPress is told it lives at a portless URL and curl
# resolves that name to the real port.
HOST="aps-multisite.localhost"
URL="http://$HOST"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "Starting multisite Playground on 127.0.0.1:$PORT as $URL (log: $WORK/server.log)..."
npx -y @wp-playground/cli@3.1.60 server --port="$PORT" --site-url="$URL" \
	--mount="$ROOT:/wordpress/wp-content/plugins/application-passwords-scoped" \
	--mount="$ROOT/tests/playground:/wordpress/wp-content/mu-plugins" \
	--blueprint="$ROOT/tests/playground/multisite-blueprint.json" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do
	grep -q Ready "$WORK/server.log" && break
	sleep 3
done
grep -q Ready "$WORK/server.log" || { cat "$WORK/server.log"; echo "Playground failed to start"; exit 1; }

CURL=( curl -s --connect-to "$HOST:80:127.0.0.1:$PORT" )
"${CURL[@]}" -L -o /dev/null "$URL/"
# Network-activate from inside a request: in a blueprint step, the freshly converted network isn't
# fully booted and the activation doesn't persist.
"${CURL[@]}" "$URL/?aps_toggle=activate&network=1" > /dev/null
"${CURL[@]}" "$URL/?aps_fixture=1" | grep -o '{.*}' > "$WORK/pw.json"
[ -s "$WORK/pw.json" ] || { echo "Fixture failed"; exit 1; }

pw() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$WORK/pw.json" "$1"; }
can() {
	"${CURL[@]}" -u "admin:$(pw "$1")" "$URL/wp-json/aps-test/v1/can/$2" | grep -o '"can":[a-z]*' | cut -d: -f2
}

PASS=0
FAIL=0
expect_can() { # scope cap expected
	local got
	got="$(can "$1" "$2")"
	if [ "$got" = "$3" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf 'FAIL %-10s %-22s expected %s, got %s\n' "$1" "$2" "$3" "$got"; fi
}

# Sanity: this really is multisite, and admin really is a super admin.
expect_can full      manage_network         true
expect_can full      manage_network_plugins true

# A role limit removes super-admin powers, which come from site_admins, not from a role.
expect_can author    manage_network         false
expect_can author    manage_network_plugins false
expect_can author    edit_posts             true

# Any capability limit, even denying a single group, drops super admin entirely for the request:
# core checks is_super_admin() directly in places, so a partial super admin can't be trusted. The
# password keeps the user's ordinary role on the site, minus anything denied.
expect_can noplugins manage_network_plugins false
expect_can noplugins manage_network         false
expect_can noplugins manage_options         true
expect_can noplugins activate_plugins       false

# is_super_admin() itself, which core calls directly in places that skip map_meta_cap: from the
# site_admins option, and from a `$super_admins` global as wp-config.php can declare.
sa() { "${CURL[@]}" -u "admin:$(pw "$1")" "$URL/wp-json/aps-test/v1/can/read$2" | grep -o '"super_admin":[a-z]*' | cut -d: -f2; }
for c in "full - true" "author - false" "readonly - true" "full ?aps_global_sa=1 true" "author ?aps_global_sa=1 false" "noplugins ?aps_global_sa=1 false"; do
	set -- $c
	q="$2"; [ "$q" = "-" ] && q=""
	got="$(sa "$1" "$q")"
	if [ "$got" = "$3" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL is_super_admin $1 ${q:-option} expected $3, got $got"; fi
done

# Request-level scopes don't limit capabilities, so super admin stays intact.
expect_can readonly  manage_network         true

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
