#!/usr/bin/env bash
#
# End-to-end smoke test: boots WordPress Playground with this plugin, creates one Application
# Password per scope, and asserts what each one may and may not do over REST and XML-RPC.
#
# Usage: tests/smoke.sh            (starts and stops its own Playground)
#        APS_URL=http://127.0.0.1:9400 tests/smoke.sh   (reuse a running server)
#
# Requires: node/npx, curl, python3.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${APS_PORT:-9400}"
URL="${APS_URL:-}"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

if [ -z "$URL" ]; then
	URL="http://127.0.0.1:$PORT"
	echo "Starting Playground on $URL (log: $WORK/server.log)..."
	npx -y @wp-playground/cli@3.1.60 server --port="$PORT" \
		--mount="$ROOT:/wordpress/wp-content/plugins/application-passwords-scoped" \
		--mount="$ROOT/tests/playground:/wordpress/wp-content/mu-plugins" \
		--blueprint="$ROOT/tests/playground/blueprint.json" > "$WORK/server.log" 2>&1 &
	SERVER_PID=$!
	for _ in $(seq 1 100); do
		grep -q Ready "$WORK/server.log" && break
		sleep 3
	done
	grep -q Ready "$WORK/server.log" || { cat "$WORK/server.log"; echo "Playground failed to start"; exit 1; }
fi

# The test blueprint deliberately has no `login` step: Playground's auto-login 302s every
# cookieless request (and loops forever on xmlrpc.php), and without it the Application
# Password is the only credential on each request.
CURL=( curl -s )

# Playground's server answers its first request after boot with a redirect; absorb it here.
"${CURL[@]}" -L -o /dev/null "$URL/"

"${CURL[@]}" "$URL/?aps_fixture=1" | grep -o '{.*}' > "$WORK/pw.json"
[ -s "$WORK/pw.json" ] || { echo "Fixture failed"; exit 1; }

pw() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$WORK/pw.json" "$1"; }

# Prints the REST error code, or "ok" for a non-error response.
rest() { # scope method path [json]
	"${CURL[@]}" -u "admin:$(pw "$1")" -X "$2" -H 'Content-Type: application/json' ${4:+-d "$4"} "$URL/wp-json$3" |
		python3 -c "import sys,json,re
raw=sys.stdin.read(); m=re.search(r'[\[{].*', raw, re.S)
try: d=json.loads(m.group(0)) if m else None
except ValueError: d=None
print(d['code'] if isinstance(d,dict) and 'code' in d and 'message' in d else ('ok' if d is not None else 'unparseable'))"
}

PASS=0
FAIL=0
expect() { # scope method path expected[|alternative...] [json]
	local got
	got="$(rest "$1" "$2" "$3" "${5:-}")"
	if [[ "|$4|" == *"|$got|"* ]]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		printf 'FAIL %-10s %-6s %-52s expected %s, got %s\n' "$1" "$2" "$3" "$4" "$got"
	fi
}

POST='{"title":"smoke","status":"publish"}'
DRAFT='{"title":"smoke","status":"draft"}'
SITE=/wp-abilities/v1/abilities/core/get-site-info/run
USER=/wp-abilities/v1/abilities/core/get-user-info/run
OOS=application_password_out_of_scope

# Unscoped: behaves exactly like core.
expect full GET  /wp/v2/plugins ok
expect full POST /wp/v2/posts ok "$POST"
expect full POST /wp/v2/users/me/application-passwords ok '{"name":"smoke-full"}'
expect full GET  "$SITE" ok

# Role ceiling (Author).
expect author GET  /wp/v2/plugins rest_cannot_view_plugins
expect author POST /wp/v2/posts ok "$POST"
expect author POST /wp/v2/settings rest_forbidden '{"blogname":"x"}'
expect author GET  "$SITE" rest_ability_cannot_execute
expect author GET  "$USER" ok

# Roles list: plugin roles are kept or dropped independently of the core ladder.
can() { # scope cap → true|false
	"${CURL[@]}" -u "admin:$(pw "$1")" "$URL/wp-json/aps-test/v1/can/$2" | python3 -c "import sys,json,re
m=re.search(r'\{.*\}', sys.stdin.read(), re.S); d=json.loads(m.group(0)) if m else {}
print(str(d.get('can')).lower())"
}
expect_can() { # scope cap expected
	local got
	got="$(can "$1" "$2")"
	if [ "$got" = "$3" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); printf 'FAIL can %-10s %-18s expected %s, got %s\n' "$1" "$2" "$3" "$got"; fi
}
expect_can full      manage_seo      true
expect_can full      moderate_forums true
expect_can author    edit_posts      true
expect_can author    manage_seo      false
expect_can author    administrator   false
expect_can dropforum manage_options  true
expect_can dropforum manage_seo      true
expect_can dropforum moderate_forums false
expect_can dropforum administrator   true
expect_can seoonly   manage_seo      true
expect_can seoonly   edit_posts      false
expect_can noroles   read            false

# Granter: a password is also capped at what whoever granted it can do.
expect_can granted   edit_others_posts true
expect_can granted   manage_seo        true
expect_can granted   manage_options    false
expect_can granted   install_plugins   false

# An admin creating a password for Eddie over REST, without sending any scope: the granter is
# recorded anyway. Admin lacks manage_newsletter, so Eddie's new password does too.
EDDIE_ID="$(pw eddie_id)"
EDDIE_PW="$("${CURL[@]}" -u "admin:$(pw full)" -H 'Content-Type: application/json' -d '{"name":"for-eddie"}' "$URL/wp-json/wp/v2/users/$EDDIE_ID/application-passwords" | python3 -c "import sys,json,re
m=re.search(r'\{.*\}', sys.stdin.read(), re.S); print(json.loads(m.group(0)).get('password',''))")"
eddie_can() { "${CURL[@]}" -u "eddie:$EDDIE_PW" "$URL/wp-json/aps-test/v1/can/$1" | grep -o '"can":[a-z]*' | cut -d: -f2; }
for pair in edit_others_posts:true manage_seo:true manage_newsletter:false; do
	got="$(eddie_can "${pair%%:*}")"
	if [ "$got" = "${pair##*:}" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL eddie-granted-by-admin ${pair%%:*} expected ${pair##*:}, got $got"; fi
done

# A scoped password can't escape by acting through another account: no editing users who can do
# more than the scope, no granting roles beyond it, and no out-of-scope default role.
ADA="$(pw ada_id)"
SAM="$(pw sam_id)"
expect full      POST "/wp/v2/users/$ADA" ok '{"first_name":"Ada"}'
expect nopublish POST "/wp/v2/users/$ADA" rest_cannot_edit '{"email":"takeover@example.test"}'
expect nopublish POST "/wp/v2/users/$SAM" ok '{"first_name":"Sam"}'
expect nopublish POST "/wp/v2/users/$SAM" rest_user_invalid_role '{"roles":["administrator"]}'
expect nopublish POST /wp/v2/users rest_user_invalid_role '{"username":"mallory","email":"mallory@example.test","password":"x-Long-Passw0rd","roles":["editor"]}'
NEW_ROLES="$("${CURL[@]}" -u "admin:$(pw nopublish)" -H 'Content-Type: application/json' \
	-d '{"username":"trent","email":"trent@example.test","password":"x-Long-Passw0rd"}' \
	"$URL/wp-json/wp/v2/users?context=edit" | python3 -c "import sys,json,re
m=re.search(r'\{.*\}', sys.stdin.read(), re.S); print(','.join(json.loads(m.group(0)).get('roles', ['?'])))")"
if [ -z "$NEW_ROLES" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL default-role user should get no role, got '$NEW_ROLES'"; fi

# Denied groups (plugins, users).
expect noplugins GET  /wp/v2/plugins rest_cannot_view_plugins
expect noplugins POST /wp/v2/settings ok '{"blogname":"Smoke"}'

# Escalation hardening applies to every scoped password.
expect author    POST /wp/v2/users/me rest_cannot_edit '{"email":"evil@example.com"}'
expect noplugins POST /wp/v2/users/me/application-passwords rest_cannot_create_application_passwords '{"name":"escape"}'

# Read-only.
expect readonly GET  /wp/v2/plugins ok
expect readonly POST /wp/v2/posts "$OOS" "$DRAFT"
expect readonly GET  "$SITE" ok

# Abilities-only with an allowlist.
expect abilities GET /wp/v2/users "$OOS"
expect abilities GET "$SITE" ok
expect abilities GET "$USER" "$OOS"
expect abilities GET /wp/v2/users/me/application-passwords/introspect ok

# Expiry. A rejected password surfaces as either code depending on environment; Playground
# reports rest_not_logged_in even for an outright wrong password.
expect expired  GET /wp/v2/users/me/application-passwords/introspect 'application_password_expired|rest_not_logged_in'
expect expiring GET /wp/v2/users/me/application-passwords/introspect ok

# XML-RPC: capability scopes work; request-level scopes refuse to authenticate.
xmlrpc() {
	"${CURL[@]}" "$URL/xmlrpc.php" -H 'Content-Type: text/xml' \
		-d "<?xml version=\"1.0\"?><methodCall><methodName>wp.getOptions</methodName><params><param><value>1</value></param><param><value>admin</value></param><param><value>$(pw "$1")</value></param></params></methodCall>"
}
if xmlrpc noplugins | grep -q 'Software Name'; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL xmlrpc noplugins should authenticate"; fi
if xmlrpc readonly | grep -q 'faultCode'; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); echo "FAIL xmlrpc readonly should be refused"; fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
