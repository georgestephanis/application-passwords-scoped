# Scoped Application Passwords — agent guide

An **exploration** of per-password scopes for WordPress Application Passwords: what a single
password may do, independent of the user who owns it. It is a prototype meant to inform a core
proposal, not a shipping plugin. Favor clarity and well-documented decisions over feature breadth.

Design discussion, gaps in core, and open questions live in **GitHub issues** on this repo. Read
the relevant issue before changing behavior it covers, and link it from your commit or PR.

## Core rule

**Every restriction is subtractive.** A scope can only remove capabilities, never grant them. The
effective permission for any check is:

```
owner can  ∧  scope allows  ∧  (granter can, if granted_by is set)
```

Any change that could let a password exceed its owner, or the user who created it for the owner,
is a security bug. The same goes for any change that lets a password widen its own scope.

## File structure

```
application-passwords-scoped.php   Thin loader: requires includes/, calls each class's init().
includes/
├── class-scope.php                Scope value object: parsing untrusted input, allows_cap(),
│                                  allows_ability(), summary(). All policy decisions live here.
├── class-capability-groups.php    Named bundles of primitive caps ("Manage plugins", …). Filterable.
├── class-scope-store.php          Persistence: user meta `_application_password_scopes`, keyed by
│                                  password UUID. Unrestricted scopes are deleted, not stored.
├── class-enforcer.php             Runtime enforcement hooks (see below). Holds per-request state.
├── class-rest.php                 `scope` field on core's /wp/v2/users/<id>/application-passwords.
├── class-admin.php                Profile + Authorize Application form fields, list-table column.
└── class-cli.php                  `wp application-password scope get|set|clear|groups`.
assets/admin.js                    Adds `scope` to core's JS REST requests via wp.hooks filters.
assets/admin.css
tests/smoke.sh                     End-to-end test against WordPress Playground (see Testing).
tests/playground/                  Test-only blueprint + mu-plugin fixture. Never shipped.
.github/blueprint.json             Public "Open in Playground" demo.
.github/setup.php                  Demo data for that blueprint (example scoped passwords, roles).
.github/screenshots/               README images.
```

## How enforcement works

Everything hangs off hooks core already ships. Don't patch or replace core behavior.

| Hook | Class | Purpose |
|---|---|---|
| `application_password_did_authenticate` | Enforcer | Record which password authenticated and load its scope. |
| `wp_authenticate_application_password_errors` | Enforcer | Fail auth for expired passwords, and for request-level scopes over XML-RPC. |
| `map_meta_cap` @ `PHP_INT_MAX` | Enforcer | Return `do_not_allow` if any required primitive cap is out of scope. The backbone. |
| `site_option_site_admins` | Enforcer | Drop a cap-limited user from super admins for the request (`is_super_admin()` skips `map_meta_cap`). |
| `rest_pre_dispatch` | Enforcer | Read-only (HTTP method) and abilities-only (route) gates. Also runs per `/batch/v1` sub-request. |
| `wp_ability_permission_result` | Enforcer | Ability allowlist; read-only passwords only run `readonly`-annotated abilities. |
| `wp_create_application_password` | Enforcer, Admin | Record `granted_by` when one user creates a password for another; no-JS authorize form. |
| `wp_delete_application_password` | Enforcer | Delete the scope with its password. |

Enforcement only applies when `$user_id` matches the user the active password authenticated as.
Checks against other users pass through untouched. `Scope::allows_cap()` calls `user_can()` on the
granter and relies on that.

### Invariants: don't break these

- A scoped password can never use `create_app_password`, `edit_app_password` or
  `delete_app_password(s)`. It also can't use `edit_user`, `delete_user`, `promote_user` or
  `remove_user` **on its own account**. Otherwise it could mint an unscoped sibling, or change the
  account's email/password and escape to a full cookie session. See `Enforcer::ESCALATION_CAPS` and
  `SELF_CAPS`.
- `granted_by` is **always set server-side** from `get_current_user_id()`, never from request
  input. Both the REST field and `Enforcer::record_granter()` overwrite whatever was submitted.
- `Scope::from_array()` takes untrusted input from REST, forms, CLI and the authorize URL. It must
  allowlist every field and drop unknown values. When a value is invalid, fail closed: an unknown
  role means *no* capabilities from that role, not "ignore the restriction".
- `roles: null` means "no role restriction". `roles: []` means "no role capabilities at all". The
  same distinction applies to `abilities`. Keep them distinct everywhere: storage, REST, the form,
  JS. Form-encoded requests turn `null` into `''`, which is why `admin.js` omits the key instead.
- `Admin::normalize_form()` (no-JS path) and `readRoles()` in `assets/admin.js` (REST path)
  implement the same mapping from form controls to `roles`. Change them together.
- The admin form must never offer a choice that enforcement would silently undo. Roles the owner
  or granter can't use are shown **disabled**, not hidden. That way the person approving sees why.

## Development setup

Requirements: PHP 7.4+, Composer, Node 20+ (for `npx` Playground), curl, python3. The plugin
needs WordPress 6.9+ (Abilities API). No build step: the JS and CSS are hand-written and enqueued
directly.

```bash
composer install       # first time: PHPCS + WordPress Coding Standards
composer phpcs         # lint (CI runs this on every push)
composer phpcbf        # auto-fix what it can
```

Always use `./vendor/bin/phpcs` (or `composer phpcs`), not a global `phpcs`: the WPCS versions
differ. `.phpcs.xml` lints the plugin file and `includes/`. When you add a PHP file elsewhere
that ships, add it there. For test and demo files, lint them explicitly:
`./vendor/bin/phpcs --standard=.phpcs.xml tests/playground/fixture.php .github/setup.php`.

## Testing

### Automated: `tests/smoke.sh`

```bash
tests/smoke.sh                                    # boots its own Playground on :9400, ~1–2 min
APS_URL=http://127.0.0.1:9400 tests/smoke.sh      # reuse a server you already started
```

It mounts this repo as the plugin and `tests/playground/` as `mu-plugins`. It then calls
`/?aps_fixture=1` to create one password per scope under test, and asserts outcomes over REST and
XML-RPC. `fixture.php` also registers `GET /wp-json/aps-test/v1/can/<cap>`, which reports
`current_user_can()` for the authenticated password. Use it to test capability rules directly.

**Add a smoke assertion for every behavior change.** Use `expect` for REST error codes and
`expect_can` for capability checks. The suite must end `N passed, 0 failed`.

### Manual: browsing the admin UI

```bash
npx -y @wp-playground/cli@3.1.60 server --port=9400 \
  --mount="$PWD:/wordpress/wp-content/plugins/application-passwords-scoped" \
  --mount="$PWD/tests/playground:/wordpress/wp-content/mu-plugins" \
  --blueprint=tests/playground/ui-blueprint.json
```

Open `http://127.0.0.1:9400/` first, which logs you in as `admin`, then go to
`/wp-admin/profile.php`. The blueprint loads the demo passwords from `.github/setup.php` and adds a
second user, **Eddie** (Editor + SEO Manager + Newsletter Editor). Open
`/wp-admin/user-edit.php?user_id=2` to test an admin scoping someone else's password:
Administrator and Newsletter Editor should be greyed out.

Use `tests/playground/ui-blueprint.json`, not `.github/blueprint.json`, locally. The public one
installs the plugin from GitHub, so it tests `trunk`, not your working tree.

### Playground gotchas (each cost real time)

- **Don't set `WP_ENVIRONMENT_TYPE` via `defineWpConfigConsts`.** It makes Playground's prepend
  file emit warnings, which break every redirect with "headers already sent". The test fixture
  enables application passwords with `wp_is_application_passwords_available` instead. Core
  otherwise disables them on plain HTTP.
- **The test blueprint has no `login` step on purpose.** Playground's auto-login 302s every
  request without its cookie, and loops forever on `xmlrpc.php`. Without auto-login, the
  application password is the only credential, which is what we want to test.
- **The server answers its first request after boot with a redirect.** `smoke.sh` sends a warm-up
  request; do the same in ad-hoc scripts.
- **`--login` on the CLI doesn't give curl a usable session.** For browser testing use the
  blueprint `login` step. If the browser lands on wp-login.php, delete the
  `playground_auto_login_already_happened` cookie left by an earlier server and reload `/`.
- **Rejected passwords report `rest_not_logged_in` in Playground**, even an outright wrong one,
  not `incorrect_password` or our `application_password_expired`. Assert on "rejected", not on
  the specific code.
- **REST `capabilities` on a user shows raw role caps, not `map_meta_cap` results.** A cap can
  appear `true` there and still fail `user_can()`, e.g. `unfiltered_html` under
  `DISALLOW_UNFILTERED_HTML`. Use the fixture's `/aps-test/v1/can/` route to check what is really
  allowed.
- Kill stale servers before restarting: `lsof -ti :9400 | xargs kill`.

## Conventions

- Namespace `Application_Passwords_Scoped`, one class per file, `class-*.php`, static `init()`.
- Text domain `application-passwords-scoped`. Translate all user-facing strings.
- WordPress Coding Standards: Yoda conditions, `wp_unslash()` before use, escape on output.
  Wherever PHPCS is silenced with `phpcs:ignore`, say why on the same line.
- Comments explain *why*, especially security reasoning and core quirks. Match the existing
  density; don't narrate what the code does.
- Policy belongs in `Scope`, hook wiring in `Enforcer`, presentation in `Admin`. Don't put
  capability decisions in the admin layer. The UI may *preview* them, as `can_grant_role()`
  does, but enforcement must never depend on the UI.
- New extension points: name filters `application_password_scope_*` and document them with a
  docblock where they're applied.

## Workflow

- Default branch `trunk`. For anything non-trivial, branch and open a PR that links the issue.
- Before committing: `composer phpcs` is clean, and `tests/smoke.sh` passes.
- If you change the admin UI, check it in a browser (see Manual testing). Update the README
  screenshot in `.github/screenshots/` if it's now out of date.
- Record design decisions and newly found core gaps as issues, not in the README. The README links
  out to them. Sub-issues group related items under a parent ("What core would need",
  "Open questions").
