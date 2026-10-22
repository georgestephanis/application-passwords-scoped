# Core gaps: workaround or core change?

For each place this plugin wants something from WordPress core, this compares what a plugin can
do today with what a core change would buy. Every workaround below was checked against WordPress
7.1 source, and the ones marked "probed" were tried in Playground.

The short version: **most gaps have a workable plugin workaround. Only #13, enforcement that
survives the plugin not running, truly needs core.** Everything else is about robustness,
convention, or a cleaner API.

| Gap | Workaround | Quality | Core still worth asking? |
| --- | --- | --- | --- |
| [#3] Metadata on the password item | Store `scope` directly on core's item | Good (probed) | Yes, low priority |
| [#4] Authenticated password outside REST | Already have it: core's REST global is set for every transport | Good (probed) | Small API cleanup |
| [#5] `is_super_admin()` filter | Filter the option **and** the `$super_admins` global | Adequate (tested) | Yes |
| [#6] Route-level `readonly` annotation | Custom key in `register_rest_route()` args | Good for opted-in routes (probed) | Yes, for adoption |
| [#7] Authorize-flow scope protocol | Plugin-defined `scope[...]` args + introspect | Good | Yes, for interop |
| [#13] Enforcement when the plugin is off | Suspend on deactivation | Partial | **Yes, required** |

## #3: Metadata on the password item

**Gap.** There's no documented place for extra data on an Application Password, so scopes live in a
separate user meta row keyed by UUID.

**Workaround: store it on the item.** Core's writers edit each item in place and save the whole
array back, so unknown keys survive. Probed: a `scope` key added to a stored item survived
`update_application_password()` (rename) and `record_application_password_usage()`, and didn't leak
into REST responses, which build their output field by field.

- **For:** one source of truth. Deleting a password deletes its scope atomically, and nothing can
  drift.
- **Against:** it relies on undocumented behaviour. A future core refactor that rebuilds items from
  known keys would silently drop scopes, and the passwords would fail *open*. The current separate
  row fails safer: if it's lost, the passwords are suspended or the scope is missing, both visible.
- **Decision:** keep the separate row for now. If core blesses a `meta` key, switch.

**Core ask:** document that extra item keys are preserved, or add a `meta` array.

## #4: The authenticated password outside REST

**Gap.** `rest_get_authenticated_app_password()` sounds REST-only.

**Workaround: it isn't.** Core sets its global from the generic `application_password_did_authenticate`
action, so it's populated on every transport. Probed: inside an XML-RPC call, it returned the
UUID of the password that authenticated. This plugin also records the UUID itself on the same
action, so it doesn't depend on the global at all.

**Core ask:** small. A transport-neutral name (`wp_get_authenticated_application_password()`) and
documentation that it works everywhere. Not blocking anything.

## #5: `is_super_admin()` has no filter

**Gap.** Core calls `is_super_admin()` directly in places that skip `map_meta_cap`, so a scoped
super admin keeps network powers unless super-admin status itself is removed.

**Workaround.** Remove the user from the super-admin list for the request, which comes from one of
two places:

1. the `site_admins` network option, filtered with `site_option_site_admins`, and
2. a `$super_admins` global that `wp-config.php` can declare. `get_super_admins()` prefers the
   global, so filtering the option alone misses it. Found during this comparison and now handled:
   the plugin narrows the global when the password authenticates. `tests/multisite.sh` checks
   `is_super_admin()` directly for both sources, and the old code fails that test.

- **Against:** it's all-or-nothing. Removing super-admin status for one denied group drops *every*
  network power for the request. It also edits a global, which is fragile if something reads it
  earlier in the request.

**Core ask:** still worth it. A `is_super_admin` filter would let a scope remove super-admin status
cleanly, and is a long-requested hook anyway.

## #6: Route-level `readonly` annotations

**Gap.** Read-only passwords decide read-versus-write by HTTP method, which is wrong for POST-based
searches and GraphQL.

**Workaround: annotate routes in their own args.** `register_rest_route()` keeps unknown keys on the
handler, and `rest_request_before_callbacks` receives the handler. Probed: a custom key on a route
was readable at dispatch. This plugin could honour, say, `'readonly' => true` on any route that
declares it, alongside the existing `application_password_scope_request_is_read_only` filter.

- **For:** declarative, sits next to the route, no extra filter.
- **Against:** only helps routes that opt in, using a key core doesn't define. A plugin-chosen key
  name is a convention nobody else follows.

**Core ask:** worth it for adoption. A core-defined annotation (matching the Abilities API's
`readonly`) would let read-only scopes allow routes by declaration instead of by method. Overlaps
[#16](https://github.com/georgestephanis/application-passwords-scoped/issues/16).

## #7: Authorize-flow scope protocol

**Gap.** No standard way for an app to request a scope, or learn what it was granted.

**Workaround: already in place.** Apps put `scope[...]` in the authorize URL. They learn the granted
scope from introspect, which every password can always call, and they can ask for more with an
access request.

Appending the granted scope to `success_url` isn't possible: core builds that redirect itself, in
PHP for no-JS and in `auth-app.js` (from the `authApp` global) for JS, with no filter on either.
Wrapping `authApp.success` or `wp_redirect` would work but is too hacky to be worth it, given
introspect covers the need with one extra request.

**Core ask:** worth it for interoperability. Apps shouldn't have to know a plugin's private
parameter format. A core-documented `scope` request format, plus the granted scope on the redirect.

## #13: Enforcement when the plugin isn't running

**Gap.** Core doesn't know passwords can be scoped. Without this plugin, every scoped password has
its owner's full access.

**Workaround: suspend on deactivation.** In place: deactivating moves each scoped password's hash
aside so it can't authenticate, and reactivating restores it.

That covers deliberate deactivation only. It can't cover the plugin fataling, its files being
removed, a restore from backup without it, or the database being moved to a site without it. Two
partial extras were considered and rejected:

- **An mu-plugin guard** that refuses scoped passwords if the main plugin isn't loaded. It covers
  fatals, but it's one more file that can itself go missing, and mu-plugins don't install themselves.
- **Hashing scoped passwords differently** so core can't verify them. That's the same suspension,
  made permanent; the plugin would then be required for the passwords to work at all, which is
  arguably right, but it means re-implementing verification and breaks if core changes hash formats
  (it did in 6.8).

**Core ask:** required for this to be trustworthy. At minimum, core should refuse a password it
knows carries a scope it can't enforce. That depends on #3: core needs to know a scope exists.

[#3]: https://github.com/georgestephanis/application-passwords-scoped/issues/3
[#4]: https://github.com/georgestephanis/application-passwords-scoped/issues/4
[#5]: https://github.com/georgestephanis/application-passwords-scoped/issues/5
[#6]: https://github.com/georgestephanis/application-passwords-scoped/issues/6
[#7]: https://github.com/georgestephanis/application-passwords-scoped/issues/7
[#13]: https://github.com/georgestephanis/application-passwords-scoped/issues/13
