<?php
/**
 * The credential the current request authenticated with.
 *
 * @package Credential_Scope
 */

namespace Credential_Scope;

/**
 * Immutable description of one credential: whose it is, what it is restricted to, who granted it
 * and when it stops working. Built by the credential type that owns its storage.
 */
final class Credential {

	/**
	 * Credential type, as registered with Credentials::register_type(): 'application_password',
	 * 'oauth', …
	 *
	 * @var string
	 */
	public $type;

	/**
	 * Identifier within the type, such as an Application Password UUID or a token ID.
	 *
	 * @var string
	 */
	public $id;

	/**
	 * User the credential authenticates as.
	 *
	 * @var int
	 */
	public $user_id;

	/**
	 * Restriction, or null for none.
	 *
	 * @var Restriction|null
	 */
	public $scope;

	/**
	 * User who issued this credential on the owner's behalf, or 0. Every capability must also
	 * pass for this user, so nobody can mint a credential for someone else that is stronger than
	 * their own. Must be set server-side, never from request input.
	 *
	 * @var int
	 */
	public $granted_by;

	/**
	 * Unix timestamp after which the credential stops working, or 0 for never.
	 *
	 * @var int
	 */
	public $expires;

	/**
	 * Constructor.
	 *
	 * @param string           $type       Credential type.
	 * @param string           $id         Identifier within the type.
	 * @param int              $user_id    Owner.
	 * @param Restriction|null $scope      Restriction, or null for none.
	 * @param int              $granted_by Granter, or 0.
	 * @param int              $expires    Expiry timestamp, or 0.
	 */
	public function __construct( $type, $id, $user_id, ?Restriction $scope = null, $granted_by = 0, $expires = 0 ) {
		$this->type       = (string) $type;
		$this->id         = (string) $id;
		$this->user_id    = (int) $user_id;
		$this->scope      = $scope;
		$this->granted_by = (int) $granted_by;
		$this->expires    = (int) $expires;
	}

	/**
	 * Whether the ceiling has anything to enforce for this credential.
	 *
	 * @return bool
	 */
	public function is_restricted() {
		return ( $this->scope && $this->scope->is_restricted() ) || $this->granted_by > 0 || $this->expires > 0;
	}

	/**
	 * Whether the credential has passed its expiry time.
	 *
	 * @return bool
	 */
	public function is_expired() {
		return $this->expires > 0 && $this->expires <= time();
	}

	/**
	 * Whether this credential removes any capabilities. A granter always does: it caps the
	 * credential at whatever the granter can do now.
	 *
	 * @return bool
	 */
	public function limits_caps() {
		return $this->granted_by > 0 || ( $this->scope && $this->scope->limits_caps() );
	}

	/**
	 * Whether a primitive capability survives both the scope and the granter.
	 *
	 * @param string $cap Primitive capability.
	 * @return bool
	 */
	public function allows_cap( $cap ) {
		if ( $this->scope && ! $this->scope->allows_cap( $cap ) ) {
			return false;
		}

		if ( $this->granted_by && 'exist' !== $cap ) {
			$granter = get_userdata( $this->granted_by );

			// user_can() re-enters map_meta_cap, but for a different user ID, so the Ceiling passes
			// it straight through. It also handles multisite super admins correctly. A deleted
			// granter fails closed.
			if ( ! $granter || ! user_can( $granter, $cap ) ) {
				return false;
			}
		}

		return true;
	}
}
