<?php
/**
 * What a credential type's scope must answer for the shared ceiling to enforce it.
 *
 * @package Credential_Scope
 */

namespace Credential_Scope;

/**
 * A restriction attached to one credential. Every answer is subtractive: a restriction can only
 * take away what the owning user could already do, never add to it.
 *
 * Granter and expiry are deliberately not part of this. They are properties of the credential,
 * not of its scope, so the layer enforces them once for every type (see Credential).
 */
interface Restriction {

	/**
	 * Whether this restriction narrows anything at all. An unrestricted credential with no
	 * granter and no expiry is left entirely alone.
	 *
	 * @return bool
	 */
	public function is_restricted();

	/**
	 * Whether this restriction removes capabilities, as opposed to only gating requests. Decides
	 * whether role lists, super admin status and user management are narrowed too.
	 *
	 * @return bool
	 */
	public function limits_caps();

	/**
	 * Whether a primitive capability survives this restriction. Runs on every capability check
	 * for the credential's user, so keep it cheap.
	 *
	 * @param string $cap Primitive capability.
	 * @return bool
	 */
	public function allows_cap( $cap );

	/**
	 * Whether an ability may be executed.
	 *
	 * @param string           $name    Ability name.
	 * @param \WP_Ability|null $ability Ability, for its annotations.
	 * @return bool
	 */
	public function allows_ability( $name, $ability = null );

	/**
	 * Whether only requests that read are allowed (see Request::is_read_only()).
	 *
	 * @return bool
	 */
	public function restricts_to_reads();

	/**
	 * Whether REST requests are limited to the Abilities API.
	 *
	 * @return bool
	 */
	public function restricts_to_abilities();

	/**
	 * Whether this restriction has rules that can only be enforced on the REST API, beyond
	 * read-only (which other endpoints can declare per request). If so, the credential must be
	 * refused anywhere else rather than let through unchecked.
	 *
	 * @return bool
	 */
	public function requires_rest();
}
