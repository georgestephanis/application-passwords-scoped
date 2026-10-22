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
	 * Roles whose capabilities this password may use, or null for no role restriction.
	 *
	 * The password can only use capabilities that BOTH the user has AND at least one of these
	 * roles grants. It's a list rather than a single ceiling because roles don't all sit on one
	 * ladder: core's Administrator > Editor > Author > Contributor > Subscriber do, but plugin
	 * roles like bbPress's Keymaster or Yoast's SEO Manager are held *alongside* them and need
	 * to be kept or dropped independently. An empty list allows no role capabilities at all.
	 *
	 * @var string[]|null
	 */
	public $roles = null;

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
	 * Refuse this password on XML-RPC entirely, leaving REST, GraphQL and other API endpoints.
	 *
	 * @var bool
	 */
	public $block_xmlrpc = false;

	/**
	 * ID of the user who created or last scoped this password on someone else's behalf, or 0.
	 *
	 * When set, every capability must ALSO pass for this user, so nobody can mint a credential for
	 * another account that's stronger than their own. Always set server-side from the acting user,
	 * never from request input. If the granter is later deleted, the password fails closed.
	 *
	 * @var int
	 */
	public $granted_by = 0;

	/**
	 * Unix timestamp after which the password stops authenticating, or 0 for never.
	 *
	 * @var int
	 */
	public $expires = 0;

	/**
	 * Cache for denied_caps(), keyed by the deny list it was built from.
	 *
	 * @var array{key: string, covered: array}|null
	 */
	private $denied_cache = null;

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

		// `role` (a single slug) is accepted as shorthand for `roles`.
		if ( ! isset( $data['roles'] ) && ! empty( $data['role'] ) && is_string( $data['role'] ) ) {
			$data['roles'] = array( $data['role'] );
		}

		if ( isset( $data['roles'] ) && null !== $data['roles'] ) {
			$roles = is_string( $data['roles'] ) ? explode( ',', $data['roles'] ) : (array) $data['roles'];

			// Unknown roles are dropped, not ignored: asking for only a role that doesn't exist
			// yields no role capabilities, failing closed.
			$scope->roles = array_values( array_unique( array_filter( array_map( 'trim', $roles ), array( wp_roles(), 'is_role' ) ) ) );
		}

		if ( ! empty( $data['deny'] ) ) {
			$deny        = is_string( $data['deny'] ) ? explode( ',', $data['deny'] ) : (array) $data['deny'];
			$valid       = array_keys( Capability_Groups::all() );
			$scope->deny = array_values( array_intersect( $valid, array_map( 'trim', $deny ) ) );
		}

		$scope->read_only      = ! empty( $data['read_only'] ) && 'false' !== $data['read_only'];
		$scope->abilities_only = ! empty( $data['abilities_only'] ) && 'false' !== $data['abilities_only'];
		$scope->block_xmlrpc   = ! empty( $data['block_xmlrpc'] ) && 'false' !== $data['block_xmlrpc'];

		$scope->granted_by = isset( $data['granted_by'] ) ? absint( $data['granted_by'] ) : 0;

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
	 * The scope a new password starts with when none is requested.
	 *
	 * @param int $user_id Owner of the new password.
	 * @return Scope
	 */
	public static function default_for( $user_id ) {
		/**
		 * Filters the scope new Application Passwords get when none is requested.
		 *
		 * Defaults to full access. Return an array of scope fields (as accepted by the REST `scope`
		 * field). People can still narrow it when creating a password.
		 *
		 * @param array $scope   Scope fields. Empty means full access.
		 * @param int   $user_id Owner of the new password.
		 */
		$data = apply_filters( 'application_password_scope_default', array(), (int) $user_id );
		$data = is_array( $data ) ? $data : array();
		unset( $data['granted_by'] );

		return self::from_array( $data );
	}

	/**
	 * Core's nested roles, highest first. Each is a superset of the next, so the UI offers them
	 * as a single "at most" choice; every other role is offered as an independent toggle.
	 *
	 * @return string[] Role slugs that exist on this site.
	 */
	public static function hierarchical_roles() {
		/**
		 * Filters the roles treated as one nested ladder rather than independent toggles.
		 *
		 * @param string[] $roles Role slugs, highest first.
		 */
		$roles = apply_filters(
			'application_password_scope_hierarchical_roles',
			array( 'administrator', 'editor', 'author', 'contributor', 'subscriber' )
		);

		return array_values( array_filter( $roles, array( wp_roles(), 'is_role' ) ) );
	}

	/**
	 * Serialize for storage / REST output.
	 *
	 * @return array
	 */
	public function to_array() {
		return array(
			'roles'          => $this->roles,
			'deny'           => $this->deny,
			'read_only'      => $this->read_only,
			'abilities'      => $this->abilities,
			'abilities_only' => $this->abilities_only,
			'block_xmlrpc'   => $this->block_xmlrpc,
			'expires'        => $this->expires,
			'granted_by'     => $this->granted_by,
		);
	}

	/**
	 * Whether this scope restricts anything at all.
	 *
	 * @return bool
	 */
	public function is_restricted() {
		return null !== $this->roles
			|| array() !== $this->deny
			|| $this->read_only
			|| null !== $this->abilities
			|| $this->abilities_only
			|| $this->block_xmlrpc
			|| $this->expires > 0
			|| $this->granted_by > 0;
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
		return null !== $this->roles || array() !== $this->deny || $this->granted_by > 0;
	}

	/**
	 * Whether a primitive capability survives this scope.
	 *
	 * @param string $cap Primitive capability.
	 * @return bool
	 */
	public function allows_cap( $cap ) {
		$allowed = $this->evaluate_cap( $cap );

		/**
		 * Filters whether a scope allows a primitive capability.
		 *
		 * Runs on every capability check for a scoped password, so keep it cheap. Returning true
		 * can't give a user a capability they don't have; it only stops the scope removing it.
		 *
		 * @param bool   $allowed Scope's decision.
		 * @param string $cap     Primitive capability.
		 * @param Scope  $scope   Scope.
		 */
		return (bool) apply_filters( 'application_password_scope_allows_cap', $allowed, $cap, $this );
	}

	/**
	 * The scope's own decision for allows_cap(), before filtering.
	 *
	 * @param string $cap Primitive capability.
	 * @return bool
	 */
	private function evaluate_cap( $cap ) {
		if ( 'exist' === $cap ) {
			return true;
		}

		if ( Capability_Groups::covers( $cap, $this->denied_caps() ) ) {
			return false;
		}

		if ( $this->granted_by ) {
			$granter = get_userdata( $this->granted_by );

			// user_can() re-enters map_meta_cap, but for a different user ID, so the Enforcer passes
			// it straight through. It also handles multisite super admins correctly.
			if ( ! $granter || ! user_can( $granter, $cap ) ) {
				return false;
			}
		}

		if ( null === $this->roles ) {
			return true;
		}

		// Role names double as capabilities (`current_user_can( 'administrator' )`).
		if ( in_array( $cap, $this->roles, true ) ) {
			return true;
		}

		foreach ( $this->roles as $slug ) {
			$role = get_role( $slug );

			// A role deleted since the scope was saved simply contributes nothing.
			if ( $role && ! empty( $role->capabilities[ $cap ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Primitive caps withheld by the denied groups. allows_cap() runs on every capability check,
	 * so don't re-run the groups filter each time.
	 *
	 * @return array caps_for() result.
	 */
	private function denied_caps() {
		$key = implode( ',', $this->deny );

		if ( null === $this->denied_cache || $key !== $this->denied_cache['key'] ) {
			$this->denied_cache = array(
				'key'     => $key,
				'covered' => Capability_Groups::caps_for( $this->deny ),
			);
		}

		return $this->denied_cache['covered'];
	}

	/**
	 * Whether an ability may be executed under this scope.
	 *
	 * @param string           $name    Ability name.
	 * @param \WP_Ability|null $ability Ability object, used for its annotations.
	 * @return bool
	 */
	public function allows_ability( $name, $ability = null ) {
		$allowed = $this->evaluate_ability( $name, $ability );

		/**
		 * Filters whether a scope allows executing an ability.
		 *
		 * @param bool             $allowed Scope's decision.
		 * @param string           $name    Ability name.
		 * @param \WP_Ability|null $ability Ability, if known.
		 * @param Scope            $scope   Scope.
		 */
		return (bool) apply_filters( 'application_password_scope_allows_ability', $allowed, $name, $ability, $this );
	}

	/**
	 * The scope's own decision for allows_ability(), before filtering.
	 *
	 * @param string           $name    Ability name.
	 * @param \WP_Ability|null $ability Ability.
	 * @return bool
	 */
	private function evaluate_ability( $name, $ability ) {
		if ( $this->read_only ) {
			$meta = $ability ? $ability->get_meta() : array();
			if ( empty( $meta['annotations']['readonly'] ) ) {
				return false;
			}
		}

		return $this->lists_ability( $name );
	}

	/**
	 * Whether an ability name is on this scope's list, by exact name or pattern. Unlike
	 * allows_ability(), ignores read-only and filters: it answers "was this listed?".
	 *
	 * @param string $name Ability name.
	 * @return bool
	 */
	public function lists_ability( $name ) {
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
	 * Whether a role is within a roles list: listed itself, or a core-ladder role at or below a
	 * listed ladder role (Author is within Editor).
	 *
	 * @param string   $slug  Role.
	 * @param string[] $roles Roles list.
	 * @return bool
	 */
	public static function role_within( $slug, array $roles ) {
		if ( in_array( $slug, $roles, true ) ) {
			return true;
		}

		$ladder = self::hierarchical_roles();
		$rank   = array_search( $slug, $ladder, true );

		if ( false === $rank ) {
			return false;
		}

		foreach ( array_intersect( $ladder, $roles ) as $listed ) {
			if ( array_search( $listed, $ladder, true ) <= $rank ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * This scope, narrowed so it allows nothing `$limit` doesn't. Used where someone may only
	 * tighten what was asked for, like approving an app's requested scope.
	 *
	 * @param Scope $limit Upper bound.
	 * @return Scope New scope.
	 */
	public function constrain_to( Scope $limit ) {
		$out               = clone $this;
		$out->denied_cache = null;

		$out->read_only      = $this->read_only || $limit->read_only;
		$out->abilities_only = $this->abilities_only || $limit->abilities_only;
		$out->block_xmlrpc   = $this->block_xmlrpc || $limit->block_xmlrpc;
		$out->deny           = array_values( array_unique( array_merge( $this->deny, $limit->deny ) ) );

		if ( null !== $limit->roles ) {
			$mine       = null === $this->roles ? $limit->roles : $this->roles;
			$out->roles = array_values(
				array_filter(
					$mine,
					static function ( $slug ) use ( $limit ) {
						return self::role_within( $slug, $limit->roles );
					}
				)
			);
		}

		if ( null !== $limit->abilities ) {
			$mine           = null === $this->abilities ? $limit->abilities : $this->abilities;
			$out->abilities = array_values( array_filter( $mine, array( $limit, 'lists_ability' ) ) );
		}

		if ( $limit->expires && ( ! $this->expires || $this->expires > $limit->expires ) ) {
			$out->expires = $limit->expires;
		}

		if ( ! $out->granted_by ) {
			$out->granted_by = $limit->granted_by;
		}

		return $out;
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

		if ( null !== $this->roles ) {
			$names  = wp_roles()->get_names();
			$labels = array();
			foreach ( $this->roles as $slug ) {
				$labels[] = translate_user_role( $names[ $slug ] ?? $slug );
			}
			$parts[] = $labels
				/* translators: %s: role names joined by " + ". */
				? sprintf( __( 'As %s', 'application-passwords-scoped' ), implode( ' + ', $labels ) )
				: __( 'No role permissions', 'application-passwords-scoped' );
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
		} elseif ( $this->block_xmlrpc ) {
			$parts[] = __( 'No XML-RPC', 'application-passwords-scoped' );
		}

		if ( null !== $this->abilities ) {
			$parts[] = $this->abilities
				/* translators: %s: comma separated list of ability names. */
				? sprintf( __( 'Abilities: %s', 'application-passwords-scoped' ), implode( ', ', $this->abilities ) )
				: __( 'No abilities', 'application-passwords-scoped' );
		}

		if ( $this->granted_by ) {
			$granter = get_userdata( $this->granted_by );
			$parts[] = $granter
				/* translators: %s: display name of the user who granted the password. */
				? sprintf( __( 'Limited to what %s can do', 'application-passwords-scoped' ), $granter->display_name )
				: __( 'Granter no longer exists (disabled)', 'application-passwords-scoped' );
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
