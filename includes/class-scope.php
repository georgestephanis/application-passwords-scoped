<?php
/**
 * Value object describing the restrictions attached to one Application Password.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

/**
 * A scope. Every restriction is subtractive: a scope can only ever take capabilities away from
 * the user who owns the password, never grant them. An empty scope is "no restrictions" and
 * behaves exactly like a core Application Password.
 */
final class Scope {

	/**
	 * Role slug acting as a capability ceiling, or '' for none.
	 *
	 * The password can only use capabilities that BOTH the user has AND this role grants.
	 *
	 * @var string
	 */
	public $role = '';

	/**
	 * Capability group slugs (see Capability_Groups) that are withheld entirely.
	 *
	 * @var string[]
	 */
	public $deny = array();

	/**
	 * Only allow safe (GET/HEAD/OPTIONS) REST requests, read-only XML-RPC methods, and
	 * abilities annotated as `readonly`.
	 *
	 * @var bool
	 */
	public $read_only = false;

	/**
	 * Ability names (wildcards allowed, e.g. `core/*`) this password may execute.
	 * `null` means abilities are not restricted beyond the other rules.
	 *
	 * @var string[]|null
	 */
	public $abilities = null;

	/**
	 * Restrict REST access to the Abilities API namespace only. Useful for agent/MCP style
	 * clients that should act exclusively through declared abilities.
	 *
	 * @var bool
	 */
	public $abilities_only = false;

	/**
	 * Unix timestamp after which the password stops authenticating, or 0 for never.
	 *
	 * @var int
	 */
	public $expires = 0;

	/**
	 * Build from untrusted array input (REST, form submission, CLI). Unknown values are dropped.
	 *
	 * @param mixed $data Raw data.
	 * @return Scope
	 */
	public static function from_array( $data ) {
		$scope = new self();

		if ( ! is_array( $data ) ) {
			return $scope;
		}

		if ( ! empty( $data['role'] ) && is_string( $data['role'] ) && wp_roles()->is_role( $data['role'] ) ) {
			$scope->role = $data['role'];
		}

		if ( ! empty( $data['deny'] ) ) {
			$deny        = is_string( $data['deny'] ) ? explode( ',', $data['deny'] ) : (array) $data['deny'];
			$valid       = array_keys( Capability_Groups::all() );
			$scope->deny = array_values( array_intersect( $valid, array_map( 'trim', $deny ) ) );
		}

		$scope->read_only      = ! empty( $data['read_only'] ) && 'false' !== $data['read_only'];
		$scope->abilities_only = ! empty( $data['abilities_only'] ) && 'false' !== $data['abilities_only'];

		if ( ! empty( $data['expires_in'] ) && (int) $data['expires_in'] > 0 ) {
			$scope->expires = time() + (int) $data['expires_in'];
		} elseif ( ! empty( $data['expires'] ) && (int) $data['expires'] > 0 ) {
			$scope->expires = (int) $data['expires'];
		}

		if ( isset( $data['abilities'] ) && null !== $data['abilities'] ) {
			$abilities = is_string( $data['abilities'] ) ? preg_split( '/[\s,]+/', $data['abilities'] ) : (array) $data['abilities'];
			$abilities = array_filter(
				array_map( 'trim', $abilities ),
				static function ( $pattern ) {
					return (bool) preg_match( '#^[a-z0-9*][a-z0-9_\-/*]*$#', $pattern );
				}
			);

			$scope->abilities = array_values( array_unique( $abilities ) );
		}

		return $scope;
	}

	/**
	 * Serialize for storage / REST output.
	 *
	 * @return array
	 */
	public function to_array() {
		return array(
			'role'           => $this->role,
			'deny'           => $this->deny,
			'read_only'      => $this->read_only,
			'abilities'      => $this->abilities,
			'abilities_only' => $this->abilities_only,
			'expires'        => $this->expires,
		);
	}

	/**
	 * Whether this scope restricts anything at all.
	 *
	 * @return bool
	 */
	public function is_restricted() {
		return '' !== $this->role
			|| array() !== $this->deny
			|| $this->read_only
			|| null !== $this->abilities
			|| $this->abilities_only
			|| $this->expires > 0;
	}

	/**
	 * Whether the scope has passed its expiry time.
	 *
	 * @return bool
	 */
	public function is_expired() {
		return $this->expires > 0 && $this->expires <= time();
	}

	/**
	 * Whether this scope removes any capabilities (as opposed to only gating requests).
	 *
	 * @return bool
	 */
	public function limits_caps() {
		return '' !== $this->role || array() !== $this->deny;
	}

	/**
	 * Whether a primitive capability survives this scope.
	 *
	 * @param string $cap Primitive capability.
	 * @return bool
	 */
	public function allows_cap( $cap ) {
		if ( 'exist' === $cap ) {
			return true;
		}

		if ( isset( Capability_Groups::caps_for( $this->deny )[ $cap ] ) ) {
			return false;
		}

		if ( '' !== $this->role ) {
			$role = get_role( $this->role );

			// A role that has since been deleted caps the password at nothing.
			if ( ! $role || empty( $role->capabilities[ $cap ] ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Whether an ability may be executed under this scope.
	 *
	 * @param string           $name    Ability name.
	 * @param \WP_Ability|null $ability Ability object, used for its annotations.
	 * @return bool
	 */
	public function allows_ability( $name, $ability = null ) {
		if ( $this->read_only ) {
			$meta = $ability ? $ability->get_meta() : array();
			if ( empty( $meta['annotations']['readonly'] ) ) {
				return false;
			}
		}

		if ( null === $this->abilities ) {
			return true;
		}

		foreach ( $this->abilities as $pattern ) {
			if ( $pattern === $name || fnmatch( $pattern, $name, FNM_NOESCAPE ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Human readable one-line summary for list tables and CLI output.
	 *
	 * @return string
	 */
	public function summary() {
		if ( ! $this->is_restricted() ) {
			return __( 'Full access', 'application-passwords-scoped' );
		}

		$parts = array();

		if ( $this->read_only ) {
			$parts[] = __( 'Read-only', 'application-passwords-scoped' );
		}

		if ( '' !== $this->role ) {
			$names = wp_roles()->get_names();
			/* translators: %s: role name. */
			$parts[] = sprintf( __( 'Up to %s', 'application-passwords-scoped' ), translate_user_role( $names[ $this->role ] ?? $this->role ) );
		}

		if ( $this->deny ) {
			$groups = Capability_Groups::all();
			$labels = array();
			foreach ( $this->deny as $slug ) {
				$labels[] = $groups[ $slug ]['label'] ?? $slug;
			}
			/* translators: %s: comma separated list of capability groups. */
			$parts[] = sprintf( __( 'Cannot: %s', 'application-passwords-scoped' ), implode( ', ', $labels ) );
		}

		if ( $this->abilities_only ) {
			$parts[] = __( 'Abilities API only', 'application-passwords-scoped' );
		}

		if ( null !== $this->abilities ) {
			$parts[] = $this->abilities
				/* translators: %s: comma separated list of ability names. */
				? sprintf( __( 'Abilities: %s', 'application-passwords-scoped' ), implode( ', ', $this->abilities ) )
				: __( 'No abilities', 'application-passwords-scoped' );
		}

		if ( $this->expires ) {
			$parts[] = $this->is_expired()
				? __( 'Expired', 'application-passwords-scoped' )
				/* translators: %s: date and time. */
				: sprintf( __( 'Expires %s', 'application-passwords-scoped' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $this->expires ) );
		}

		return implode( ' · ', $parts );
	}
}
