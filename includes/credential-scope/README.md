# Credential Scope

A capability ceiling that any authentication method can attach to: Application Passwords,
OAuth, API keys. Nothing in this directory knows about Application Passwords. It lives inside
Scoped Application Passwords for now, but is kept separate so it can be lifted out as a library,
or proposed to core on its own. Background and alternatives: [#17].

## The rule

For any capability check by the user a credential authenticated as:

```text
owner can  ∧  scope allows  ∧  (granter can, if granted_by is set)
```

Every restriction is subtractive. A credential can never exceed its owner, or whoever issued it
for the owner.

## What lives here, and what doesn't

| Here (shared by every credential type) | In each credential type |
| --- | --- |
| The `map_meta_cap` ceiling, and narrowing super admins | Storage of credentials and scopes |
| Escalation caps: no restricted credential may manage credentials of *any* registered type | Its UI, and its scope format |
| No acting on your own account, or on stronger ones | Authentication itself |
| No granting roles you couldn't exercise (`editable_roles`, `default_role`) | Calling `validate()` at its own rejection point |
| REST read-only and abilities-only gates, ability allowlist | Type-specific rules (e.g. blocking XML-RPC) |
| What "read-only" means (`Request::is_read_only()`) | |
| Granter semantics, and the cascade when a granter is deleted or demoted | Listing and revoking its own credentials |
| Expiry semantics, failing closed if a type forgets to check | |

## Integrating a credential type

```php
use Credential_Scope\Credential;
use Credential_Scope\Credentials;

// Once, at load.
Credentials::register_type(
	'my_tokens',
	array(
		'escalation_caps' => array( 'manage_my_tokens' ), // Caps that create or edit tokens.
		'granted_by'      => 'my_tokens_issued_by',      // fn( int[] ): rows (see Credentials).
		'revoke'          => 'my_tokens_revoke',         // fn( int $user_id, string $id ).
	)
);

// When a request authenticates. $scope implements Credential_Scope\Restriction, or is null.
$credential = new Credential( 'my_tokens', $token_id, $user_id, $scope, $granted_by, $expires );

if ( Credentials::validate( $credential )->has_errors() ) {
	// Reject authentication, the same way as a wrong token.
}

Credentials::set_current( $credential );
```

`Restriction` is the interface a scope implements. Scoped Application Passwords' `Scope` is one
implementation; an OAuth server might map scope strings onto another.

## Known limits

- **It fails open on non-adoption.** An authentication method that resolves a user without
  calling `set_current()` gets no ceiling. The smoke test's `undeclared` token shows this. Core
  could narrow it (e.g. warn when `determine_current_user` changes the user and no credential was
  declared), but can't close it.
- **One credential per request.** Nothing here handles two credentials on one request.
- **Request gates are REST only.** Elsewhere, read-only holds only where the request is known to
  read (XML-RPC `get*`, or a plugin's `credential_scope_request_is_read_only`), and credentials
  with ability rules are refused.
- **Strings use the host plugin's text domain**, `application-passwords-scoped`. Give it its
  own when severing.

## Hooks

| Hook | Type | Purpose |
| --- | --- | --- |
| `credential_scope_authenticated` | action | A credential authenticated, restricted or not. |
| `credential_scope_escalation_caps` | filter | Add caps guarding credentials your plugin issues, even without registering a type. |
| `credential_scope_request_is_read_only` | filter | Declare whether a request only reads. |
| `credential_scope_request_exempt` | filter | Let a credential reach routes that only report or request its own access. |
| `credential_scope_revoke_granted` | filter | Revoke credentials someone issued when they're deleted or demoted. |

[#17]: https://github.com/georgestephanis/application-passwords-scoped/issues/17
