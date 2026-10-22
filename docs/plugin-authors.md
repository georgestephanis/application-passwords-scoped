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

You can also add a group of your own. It appears on the scope form for people to deny:

```php
add_filter(
	'application_password_scope_capability_groups',
	function ( $groups ) {
		$groups['shop_orders'] = array(
			'label'       => __( 'Manage orders', 'my-shop' ),
			'description' => __( 'View, edit and refund customer orders.', 'my-shop' ),
			'caps'        => array( 'edit_shop_orders', 'delete_shop_orders', 'refund_shop_orders' ),
		);
		return $groups;
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
- **Read-only passwords can only make `GET`, `HEAD` and `OPTIONS` requests.** Never change state on
  a `GET` route, or a read-only password will be able to change it.
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
capability scopes apply there, because they work on `current_user_can()`. Read-only and
ability restrictions can't, since only the REST API exposes what a request does. Passwords
with those restrictions are refused on your endpoint.

## Questions or gaps

Open an issue, or comment on
[#15](https://github.com/georgestephanis/application-passwords-scoped/issues/15).
