# Scoped Application Passwords for plugin authors

If your plugin adds capabilities, roles, REST routes or abilities, this explains how they behave
when a request is authenticated by a scoped Application Password. In short: **if you check
permissions with `current_user_can()`, scopes already apply to you.**

## How a scope decides

Every capability check made for the authenticated user goes through `map_meta_cap`. The scope looks
at each primitive capability that comes out of it. If any one of them is outside the scope, the
whole check is denied. That happens before `user_has_cap`, so it applies whether the capability
comes from a role, from user meta, or from your own `user_has_cap` filter.

A capability is outside the scope when:

- the scope lists **roles**, and none of those roles grants that capability, or
- it belongs to a **denied capability group**, or
- the password was created by someone else (**`granted_by`**), and that person can't use it.

Scopes only ever remove access. Nothing here can give a user a capability they don't already have.

## Your capabilities

**Role limits cover your capabilities automatically.** A password scoped to `author` can't use
`manage_woocommerce`, because the Author role doesn't grant it. There's nothing for you to do.

**Capability groups don't**, because they're fixed lists. The built-in "Change site settings" group
can't know about `manage_woocommerce`. If your plugin has capabilities that clearly belong in a
group, add them:

```php
add_filter(
	'application_password_scope_capability_groups',
	function ( $groups ) {
		$groups['settings']['caps'][] = 'manage_woocommerce';
		return $groups;
	}
);
```

You can also register a group of your own. It appears on the scope form for people to deny.
Capabilities can be wildcard patterns, so the group keeps covering capabilities you add later:

```php
add_action(
	'init',
	function () {
		if ( class_exists( 'Application_Passwords_Scoped\Capability_Groups' ) ) {
			Application_Passwords_Scoped\Capability_Groups::register(
				'shop_orders',
				array(
					'label'       => __( 'Manage orders', 'my-shop' ),
					'description' => __( 'View, edit and refund customer orders.', 'my-shop' ),
					'caps'        => array( '*_shop_order', '*_shop_orders', 'refund_shop_orders' ),
				)
			);
		}
	}
);
```

## Your roles

Core's roles nest: Administrator, Editor, Author, Contributor, Subscriber, each containing the
next. The scope form shows those as radio buttons ("act as at most…"). Every other role a user
holds, such as yours, appears as its own checkbox that can be kept or dropped independently.

If your roles form their own ladder that belongs with core's, filter
`application_password_scope_hierarchical_roles`. Most plugins shouldn't need to.

**Role-name checks work, but are coarse.** `current_user_can( 'shop_manager' )` passes only if
`shop_manager` is one of the scope's roles. A password scoped to Author + Shop Manager passes; one
scoped to Author alone doesn't. Prefer real capabilities, which scope precisely.

## Your REST routes

- Use a `permission_callback` that calls `current_user_can()`. Scopes then apply with no extra
  work. A `__return_true` route is reachable by any authenticated password, and by anyone else.
- **Read-only passwords can only make `GET`, `HEAD` and `OPTIONS` requests** by default. Never change
  state on a `GET` route, or a read-only password will be able to change it. If a route reads
  despite using `POST` (a complex search, say), or a `GET` route writes, tell the scope with
  `application_password_scope_request_is_read_only`, below.
- **Abilities-only passwords can't reach your routes at all.** Expose what agents need as
  abilities instead.

## Your abilities

- Abilities are the best fit for scoped access. A person can allow or deny them by name, and
  abilities-only passwords can't do anything else.
- Annotate them accurately. Read-only passwords may only run abilities with
  `'annotations' => array( 'readonly' => true )`.
- Your `permission_callback` should still check a capability. Scopes apply on top of it, so an
  ability allowed by name still fails if the password's role limit doesn't include the capability.

## Endpoints outside the REST API

If you opt an endpoint into Application Password auth with `application_password_is_api_request`,
capability scopes apply there, because they work on `current_user_can()`. Ability restrictions
can't, so passwords with them are refused on your endpoint.

Read-only passwords are refused too, **unless you say which requests only read**. A GraphQL
endpoint, for example, sends queries and mutations alike as `POST`:

```php
add_filter(
	'application_password_scope_request_is_read_only',
	function ( $is_read_only, $request, $xmlrpc_method ) {
		if ( null === $request && my_plugin_is_graphql_request() ) {
			return ! my_plugin_operation_is_mutation();
		}
		return $is_read_only;
	},
	10,
	3
);
```

`$request` is the `WP_REST_Request` on REST, and `null` elsewhere. `$xmlrpc_method` is the method
name on XML-RPC, where the default treats `get*` and `supported*` methods as reads. Return `true`
only if the request truly can't change anything: read-only passwords trust your answer.

## Filters and actions

| Hook | Use it to |
| --- | --- |
| `application_password_scope_capability_groups` | Add, change or remove capability groups. |
| `application_password_scope_hierarchical_roles` | Change which roles form the "at most" ladder. |
| `application_password_scope_request_is_read_only` | Say whether a request only reads. |
| `application_password_scope_allows_cap` | Override the scope's decision for one capability (can't grant what the user lacks). |
| `application_password_scope_allows_ability` | Override the scope's decision for one ability. |
| `application_password_scope_default` | Set the scope new passwords start with (default: full access). |
| `application_password_scope` | Adjust the scope applied to an authenticated request. |
| `application_password_scope_revoke_granted` | Revoke passwords someone created for others when they're deleted or demoted. |
| `application_password_scope_saved` (action) | React to a scope being saved from REST, a form or an approved access request. |
| `application_password_scope_access_requested` (action) | Notify the owner another way when an app asks for more access. |
| `application_password_scope_access_decided` (action) | React to an access request being approved or denied. |

## Questions or gaps

[Open an issue](https://github.com/georgestephanis/application-passwords-scoped/issues/new). For why
things work the way they do, see [design-decisions.md](design-decisions.md).
