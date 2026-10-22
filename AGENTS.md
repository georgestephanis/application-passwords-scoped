# Scoped Application Passwords — agent guide

An **exploration** of per-password scopes for WordPress Application Passwords: what a single
password may do, independent of the user who owns it. It is a prototype meant to inform a core
proposal, not a shipping plugin. Favor clarity and well-documented decisions over feature breadth.

Design discussion, gaps in core, and open questions live in **GitHub issues** on this repo. Read
the relevant issue before changing behavior it covers, and link it from your commit or PR.

## Core rule

**Every restriction is subtractive.** A scope can only remove capabilities, never grant them. The
effective permission for any check is:

```text
owner can  ∧  scope allows  ∧  (granter can, if granted_by is set)
```

Any change that could let a password exceed its owner, or the user who created it for the owner,
is a security bug. The same goes for any change that lets a password widen its own scope.

## File structure

```text
application-passwords-scoped.php   Thin loader: requires includes/, calls each class's init().
uninstall.php                      Deletes stored scopes. Core's passwords are left alone.
includes/
├── class-scope.php                Scope value object: parsing untrusted input, allows_cap(),
│                                  allows_ability(), summary(). All policy decisions live here.
├── class-capability-groups.php    Named bundles of primitive caps ("Manage plugins", …). Filterable.
├── class-scope-store.php          Persistence: user meta `_application_password_scopes`, keyed by
│                                  password UUID. Unrestricted scopes are deleted, not stored.
├── class-enforcer.php             Runtime enforcement hooks (see below). Holds per-request state.
├── class-rest.php                 `scope` field on core's /wp/v2/users/<id>/application-passwords.
├── class-admin.php                Profile + Authorize Application form fields, list-table column,
│                                  Plugins-screen and delete-user warnings.
├── class-lifecycle.php            Suspends scoped passwords on deactivation, restores on activation.
├── class-access-requests.php      Apps asking for a broader scope; owner approves/denies (#8).
└── class-cli.php                  `wp application-password scope get|set|clear|groups`.
assets/admin.js                    Adds `scope` to core's JS REST requests via wp.hooks filters.
assets/admin.css
tests/smoke.sh                     End-to-end test against WordPress Playground (see Testing).
tests/multisite.sh                 Multisite/super-admin test, on its own Playground network.
docs/plugin-authors.md             How plugin capabilities, roles, routes and abilities meet scopes.
tests/playground/                  Test-only blueprint + mu-plugin fixture. Never shipped.
.github/blueprint.json             Public "Open in Playground" demo.
.github/setup.php                  Demo data for that blueprint (example scoped passwords, roles).
.github/screenshots/               README images.
.github/workflows/lint.yml         CI: composer lint:php + npm run lint.
.phpcs.xml                         WordPress + PHPCompatibilityWP ruleset, covers all PHP files.
package.json                       @wordpress/scripts (lint/format only, no build), pinned.
.editorconfig, .nvmrc              WordPress core's editor settings; Node version for CI.
```

## How enforcement works

Everything hangs off hooks core already ships. Don't patch or replace core behavior.

| Hook | Class | Purpose |
| --- | --- | --- |
| `application_password_did_authenticate` | Enforcer | Record which password authenticated and load its scope. |
| `wp_authenticate_application_password_errors` | Enforcer | Fail auth for expired passwords, Block XML-RPC, and request-level scopes off REST unless the request is read-only (XML-RPC `get*`, plugin-declared). XML-RPC authenticates per method call, so this sees the method name. |
| `map_meta_cap` @ `PHP_INT_MAX` | Enforcer | Return `do_not_allow` if any required primitive cap is out of scope. The backbone. |
| `editable_roles` | Enforcer | Hide roles the scope couldn't exercise, so a scoped password can't create or promote users into them. |
| `rest_pre_insert_user` | Enforcer | A user created without `roles` gets no role if `default_role` is out of scope. |
| `site_option_site_admins` | Enforcer | Drop a cap-limited user from super admins for the request (`is_super_admin()` skips `map_meta_cap`). |
| `rest_pre_dispatch` @ `PHP_INT_MIN` | Enforcer | Read-only (HTTP method) and abilities-only (route) gates, before any plugin can short-circuit. Also runs per `/batch/v1` sub-request. |
| `rest_request_before_callbacks` @ `PHP_INT_MAX` | Enforcer | The same gates again, immediately before the route's permission callback and handler. |
| `rest_post_dispatch` @ `PHP_INT_MAX` | Enforcer | The same gates on the way out, so an out-of-scope response is never returned, even if a plugin overrode the error. |
| `delete_user`, `wpmu_delete_user`, `set_user_role`, `remove_user_role` | Enforcer | Offer the granter's passwords to `application_password_scope_revoke_granted` (#12). |
| `wp_ability_permission_result` | Enforcer | Ability allowlist; read-only passwords only run `readonly`-annotated abilities. |
| `wp_create_application_password` | Enforcer, Admin | Record `granted_by` when one user creates a password for another; no-JS authorize form. |
| `wp_delete_application_password` | Enforcer | Delete the scope with its password. |
| `after_plugin_row_<plugin>` | Admin | Warn that deactivating suspends scoped passwords (#13). |
| `delete_user_form` | Admin | List passwords the deleted user granted, which will stop working (#12). |
| activation / deactivation | Lifecycle | Restore / suspend scoped passwords' hashes (#13). Network-wide on multisite. |

Enforcement only applies when `$user_id` matches the user the active password authenticated as.
Checks against other users pass through untouched. `Scope::allows_cap()` calls `user_can()` on the
granter and relies on that.

### Invariants: don't break these

- **A scoped password must not be able to escape through any account, its own or anyone else's.**
    - It can never use `create_app_password`, `edit_app_password` or `delete_app_password(s)`, so it
      can't mint an unscoped sibling or rewrite its own scope (`Enforcer::ESCALATION_CAPS`).
    - It can't use `edit_user`, `delete_user`, `promote_user` or `remove_user` on its own account,
      or on any account that can do more than the scope allows (`Enforcer::may_manage_user()`).
      Otherwise it could reset that account's email or password and log in as it.
    - It can't give anyone a role it couldn't exercise itself, whether by explicit `roles` or by the
      site's `default_role`.

  When you add a capability rule, ask what else the password could do to get it back: create a
  user, edit a user, reset a password, install a plugin. Add a smoke test that tries the escape,
  and check it fails against the old code.
- `granted_by` is **always set server-side**, never from request input. Every save from a request,
  form or approval goes through `Scope_Store::save_from_request()`: a non-owner acting becomes the
  granter, and an owner editing keeps the existing one.
- **Read-only is decided by `Enforcer::is_read_only()`** and nowhere else. On REST it uses the
  effective method after `_method` / `X-HTTP-Method-Override`, so an override can't disguise a write.
- **Access requests and introspect are the only things a restricted password can always do.**
  Neither changes what it may do; only an owner's approval can. Keep it that way.
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

Requirements: PHP 7.4+, Composer, Node 24 (see `.nvmrc`; 22.22+ works), curl, python3. The plugin
needs WordPress 6.9+ (Abilities API). There's no build step: the JS and CSS are hand-written and
enqueued directly. `@wordpress/scripts` is used only for linting and formatting.

```bash
composer install              # PHPCS, WordPress Coding Standards, PHPCompatibilityWP
npm ci --ignore-scripts       # @wordpress/scripts (no install scripts needed for linting)

composer lint:php             # PHPCS: WordPress + PHPCompatibilityWP (PHP 7.4+)
composer format:php           # PHPCBF auto-fix
npm run lint                  # lint:js, lint:style, lint:pkg-json, lint:md:docs
npm run format                # Prettier (wp-prettier) on assets/
npm run test:smoke            # tests/smoke.sh
```

CI (`.github/workflows/lint.yml`) runs `composer lint:php` and `npm run lint` on every push to
`trunk` and on every pull request. Both must pass.

- **PHP:** `.phpcs.xml` covers every PHP file in the repo, including tests and demo setup. When
  you add a PHP file outside those paths, add it there. Always use `composer lint:php` (or
  `./vendor/bin/phpcs`), not a global `phpcs`: WPCS versions differ.
- **JS/CSS:** `@wordpress/scripts` is pinned to an exact version. When you upgrade it, choose a
  release at least two weeks old, then run `npm run format` and `npm run lint`, since its
  Prettier and stylelint rules change between majors. `assets/admin.js` declares
  `/* global jQuery */`: it runs in wp-admin with core's jQuery and `wp.hooks`, and isn't bundled.
- **Docs:** `npm run lint:md:docs` lints `README.md` and `AGENTS.md`. Give fenced code blocks a
  language, and use `| a | b |` table spacing.

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

### Automated: `tests/multisite.sh`

```bash
tests/multisite.sh      # its own network on :9401, ~1–2 min
```

Multisite refuses non-default ports, so the server runs with
`--site-url=http://aps-multisite.localhost` and curl uses `--connect-to` to reach port 9401. The
blueprint converts the site to a network in PHP: the `enableMultisite` step downloads
`wp-cli.phar` from playground.wordpress.net, which isn't always reachable. The plugin is
network-activated from inside a request (`?aps_toggle=activate&network=1`), because activating it
from a blueprint step doesn't persist on a freshly converted network.

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
- Before committing: `composer lint:php` and `npm run lint` are clean, and `tests/smoke.sh` passes.
  Run `tests/multisite.sh` too for anything touching capabilities, roles or super admins.
- If you change the admin UI, check it in a browser (see Manual testing). Update the README
  screenshot in `.github/screenshots/` if it's now out of date.
- Record design decisions and newly found core gaps as issues, not in the README. The README links
  out to them. Sub-issues group related items under a parent ("What core would need",
  "Open questions").
