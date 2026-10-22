# Design decisions and lessons

Why this prototype works the way it does, and what was learned building it. Each decision links to
the issue where it was discussed. For the gaps that need WordPress core, see
[core-gaps.md](core-gaps.md).

## Decisions

### Every restriction is subtractive

A scope can only remove what the owner can already do. The effective rule for every check is:

```text
owner can  ∧  scope allows  ∧  (granter can, if there is one)
```

**Why:** it makes the model easy to reason about and to audit. No setting, filter or bug in the
scope can create access that didn't exist; at worst it fails to remove some. The
`application_password_scope_allows_cap` filter keeps this property: returning `true` only stops the
scope removing a capability.

### Enforce on capabilities, gate requests separately

Most restrictions (roles, denied groups, granter) are applied to **primitive capabilities** in
`map_meta_cap`. Only things that can't be expressed as capabilities (read-only, abilities-only) are
**request gates**.

**Why:** capability checks run everywhere: REST, XML-RPC, abilities, admin-ajax, plugin code. One
filter covers all of them, including plugins this project has never heard of. Request gates only
exist where a request's intent is visible, so they're the weaker layer and are kept small.

### Roles are a list: a ladder plus independent roles

Core's roles nest (Administrator ⊃ Editor ⊃ …), but plugin roles like SEO Manager or Forum
Keymaster are held *alongside* them. A scope stores a list of roles. The UI shows the core ladder
as "at most" radios and every other role as its own checkbox.

**Why:** a single "at most X" ceiling can't say "keep SEO Manager, drop Keymaster". Raw
capabilities are too fine-grained for people approving an app. Roles are what people already
understand.

### Roles *and* capability groups

**Why both:** roles answer "act as this kind of user", and automatically cover capabilities from
plugins nobody anticipated. Groups answer "everything except the dangerous parts", which suits a
trusted integration that still shouldn't be able to install plugins. Plugins can register groups,
with wildcards, so new capabilities stay covered (#10).

### A password can't exceed whoever created it (#12)

When one user creates or scopes another user's password, the creator is recorded as **granter**,
server-side and never from input. Every capability must then also pass for the granter.

**Why:** otherwise an admin could mint a credential stronger than their own, for example a site
admin creating a password for a network super admin.

**When the granter changes:** the password narrows with them, and fails closed if they're deleted.
That needs no bookkeeping and can't fail open. Sites that prefer to revoke instead can say so with
`application_password_scope_revoke_granted`. The delete-user screen lists affected passwords so
nothing breaks silently.

### Approvers narrow; apps ask for more (#8)

On the authorize screen, the app's requested scope is the ceiling: broader options aren't offered.
An app that needs more later files an **access request** with its own password, and the owner
approves or denies it.

**Why:** offering extra checkboxes invites granting more than an app asked for. An explicit
request, with the app's reason and a side-by-side comparison, is a better moment for consent.
Narrowing isn't enforced on the REST `scope` field itself, because anyone who can call it can
already create the password with any scope.

### Scopes are editable (#9); defaults are full access (#11)

Scopes can be changed after creation, so tightening an integration doesn't mean reissuing its
password. New passwords default to full access, matching core today. Sites can set a different
default, and people narrow from whatever the default is.

### Restricted passwords can always see and ask, never widen

A restricted password can always call introspect and file an access request. It can never create,
edit or delete Application Passwords, edit its own account, or manage any account more powerful
than its scope.

**Why:** each of those is an escape hatch. The account ones were found in review: a password
limited to "no publishing" could reset another administrator's password and log in as them.
Tests now try each escape, and are checked to fail against the old code.

### Read-only is decided per request, by whoever knows

On REST, read-only means `GET`/`HEAD`/`OPTIONS`, using the effective method after `_method` and
`X-HTTP-Method-Override`. On XML-RPC, it's by method name (`get*`, `supported*`; never
`system.multicall`). Anywhere else, a plugin must declare it, which is how GraphQL queries work
(#16). Any password can also block XML-RPC outright.

**Why:** HTTP method is a weak signal outside plain REST. GraphQL sends everything as `POST`; some
REST routes `POST` to search. The plugin that owns an endpoint is the only party that knows.

### Fail closed when a restriction can't be enforced

Where a restriction can't be applied, the password is refused rather than allowed through. For
example, ability restrictions off REST, or read-only on an endpoint that hasn't declared which
requests read.

### Deactivation suspends, it doesn't unlock (#13)

Deactivating the plugin moves scoped passwords' hashes aside so they can't authenticate.
Reactivating restores them.

**Why:** without the plugin, core would honour them with full access. Suspension is the only
plugin-side way to avoid that. It's reversible, so nobody loses credentials.

### Abilities executed directly in PHP are out of scope (#14)

Scopes govern what a credential can do over an API. Plugin code that calls an ability's callback
directly is already-trusted server code, not something a password controls.

## Lessons

These cost real time. Most also appear as rules in [AGENTS.md](../AGENTS.md).

- **Check every way back in.** Blocking a capability means little if the password can create a
  user, reset someone's password, or assign a role that has it. Each fix here came from asking "how
  else could it get this back?".
- **Make the test fail first.** Several tests passed on their first run because they didn't
  exercise the bug (a role both users held, a request that never authenticated). Running each new
  test against the old code caught that.
- **`is_super_admin()` has two sources.** The `site_admins` option *and* a `$super_admins` global
  that `wp-config.php` can set, which takes precedence. Filtering only the option left super
  admins intact on sites using the global.
- **Disabled inputs aren't submitted, and nested forms count as changes.** Restrictions locked on
  the authorize screen had to be carried separately for the no-JS path. Inline editors inside the
  profile form had to drop their `name` attributes, or they'd submit with the profile and trigger
  "Leave site?".
- **`null` and empty are different, and form encoding erases the difference.** "No role
  restriction" and "no roles at all" must stay distinct through PHP, REST, forms and JS.
- **Wrong tests look like failures in the code.** An XML-RPC method was called with the wrong
  argument order, and a REST suspension was expected to report "can't" when it rejects login
  outright. Read core's implementation before deciding which side is wrong.
- **Playground has quirks worth knowing.** Auto-login redirects, custom ports breaking multisite,
  and blueprint steps on a fresh network not persisting are all written up in AGENTS.md.
