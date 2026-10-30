<?php
/**
 * Applies the current credential's restrictions to the request, whatever authenticated it.
 *
 * @package Credential_Scope
 */

namespace Credential_Scope;

use WP_Error;

/**
 * The ceiling. The effective permission for any check by the credential's user is
 * `owner can ∧ scope allows ∧ (granter can, if granted_by is set)`.
 *
 * Enforcement happens at three layers:
 *
 * 1. Capabilities (`map_meta_cap`): every capability check for the authenticated user is reduced
 *    to its primitive caps, and if any of them falls outside the scope the check gets
 *    `do_not_allow`. This is the backbone — it covers REST, XML-RPC, Abilities, and any plugin
 *    code that calls `current_user_can()`, and `do_not_allow` beats even multisite super admins.
 * 2. Requests: coarse gates that aren't expressible as capabilities — read-only (HTTP method)
 *    and abilities-only (route namespace). Checked twice: first thing in `rest_pre_dispatch`, so a
 *    plugin's own short-circuit handler can't run first, and last thing in
 *    `rest_request_before_callbacks`, immediately before the route's permission and callback, so
 *    no other filter can override it. Both run per sub-request in `/batch/v1` too. A plugin that
 *    short-circuits `rest_pre_dispatch` while ignoring an existing result can still run its own
 *    code, which nothing outside it can prevent. `rest_post_dispatch` replaces its response with
 *    the error, though, so out-of-scope data never reaches the client.
 * 3. Abilities (`wp_ability_permission_result`): an allowlist of ability names, and read-only
 *    credentials may only run abilities annotated `readonly`.
 *
 * Enforcement only applies when the user being checked is the one the credential authenticated
 * as. Checks against other users pass through untouched, which Credential::allows_cap() relies on
 * when it asks whether the granter can.
 */
class Ceiling {

	/**
	 * Meta capabilities that act on another user account. A restricted credential can't use them
	 * on its own account, or on any account that can do more than the scope allows. Otherwise it
	 * could reset that account's password or email and log in as it, escaping the scope.
	 */
	const USER_CAPS = array( 'edit_user', 'delete_user', 'remove_user', 'promote_user' );

	/**
	 * Whether the current credential's request-level rules can be enforced on this request,
	 * decided once when it authenticates.
	 *
	 * @var bool
	 */
	private static $enforceable = true;

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'credential_scope_authenticated', array( __CLASS__, 'authenticated' ) );
		add_filter( 'site_option_site_admins', array( __CLASS__, 'filter_super_admins' ) );
		add_filter( 'map_meta_cap', array( __CLASS__, 'map_meta_cap' ), PHP_INT_MAX, 4 );
		add_filter( 'editable_roles', array( __CLASS__, 'editable_roles' ), PHP_INT_MAX );
		add_filter( 'rest_pre_insert_user', array( __CLASS__, 'default_role_for_new_user' ), PHP_INT_MAX );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'rest_pre_dispatch' ), PHP_INT_MIN, 3 );
		add_filter( 'rest_request_before_callbacks', array( __CLASS__, 'rest_before_callbacks' ), PHP_INT_MAX, 3 );
		add_filter( 'rest_post_dispatch', array( __CLASS__, 'rest_post_dispatch' ), PHP_INT_MAX, 3 );
		add_filter( 'wp_ability_permission_result', array( __CLASS__, 'ability_permission' ), 10, 4 );
		add_action( 'delete_user', array( __CLASS__, 'granter_deleted' ) );
		add_action( 'wpmu_delete_user', array( __CLASS__, 'granter_deleted' ) );
		add_action( 'set_user_role', array( __CLASS__, 'granter_role_changed' ), 10, 3 );
		add_action( 'remove_user_role', array( __CLASS__, 'granter_role_changed' ), 10, 2 );
	}

	/**
	 * The restricted credential, if it applies to a user being checked.
	 *
	 * @param int $user_id User being checked.
	 * @return Credential|null
	 */
	private static function for_user( $user_id ) {
		$credential = Credentials::current();

		return $credential && (int) $user_id === $credential->user_id ? $credential : null;
	}

	/**
	 * A credential just authenticated.
	 *
	 * @param Credential $credential Credential.
	 */
	public static function authenticated( Credential $credential ) {
		self::$enforceable = ! $credential->scope || Request::can_enforce( $credential->scope );

		// get_super_admins() prefers a `$super_admins` global (set in wp-config.php) over the
		// site_admins option, so filtering the option alone misses those sites.
		if ( $credential->is_restricted() && $credential->limits_caps() && isset( $GLOBALS['super_admins'] ) && is_array( $GLOBALS['super_admins'] ) ) {
			$user = get_userdata( $credential->user_id );
			if ( $user ) {
				$GLOBALS['super_admins'] = array_values( array_diff( $GLOBALS['super_admins'], array( $user->user_login ) ) ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Narrowing super admins for this request only.
			}
		}
	}

	/**
	 * Drop a capability-limited user from the multisite super admin list for this request.
	 *
	 * `is_super_admin()` reads the `site_admins` network option directly and is checked all over
	 * core without going through `map_meta_cap`, so `do_not_allow` alone isn't enough.
	 * (Same technique as georgestephanis/t3admin, in reverse.)
	 *
	 * @param mixed $super_admins Value of the site_admins network option.
	 * @return mixed
	 */
	public static function filter_super_admins( $super_admins ) {
		$credential = Credentials::current();

		if ( ! $credential || ! $credential->limits_caps() || ! is_array( $super_admins ) ) {
			return $super_admins;
		}

		$user = get_userdata( $credential->user_id );

		if ( $user ) {
			$super_admins = array_values( array_diff( $super_admins, array( $user->user_login ) ) );
		}

		return $super_admins;
	}

	/**
	 * Reduce capability checks to what the credential allows.
	 *
	 * @param string[] $caps    Primitive caps required.
	 * @param string   $cap     Capability being checked.
	 * @param int      $user_id User being checked.
	 * @param array    $args    Extra args (e.g. object ID).
	 * @return string[]
	 */
	public static function map_meta_cap( $caps, $cap, $user_id, $args ) {
		$credential = self::for_user( $user_id );

		if ( ! $credential ) {
			return $caps;
		}

		// A credential its authentication method should have rejected, but didn't.
		if ( $credential->is_expired() || ! self::$enforceable ) {
			return array( 'do_not_allow' );
		}

		if ( in_array( $cap, Credentials::escalation_caps(), true ) ) {
			return array( 'do_not_allow' );
		}

		if ( in_array( $cap, self::USER_CAPS, true ) && isset( $args[0] ) && ! self::may_manage_user( $credential, (int) $args[0] ) ) {
			return array( 'do_not_allow' );
		}

		foreach ( $caps as $primitive ) {
			if ( ! $credential->allows_cap( $primitive ) ) {
				return array( 'do_not_allow' );
			}
		}

		return $caps;
	}

	/**
	 * Whether a restricted credential may act on another user account.
	 *
	 * Never its own account. For others, only when the credential limits no capabilities, or the
	 * target can do nothing the credential forbids. A credential scoped to Author can still edit a
	 * Subscriber's profile, if the user could, but not an Editor's.
	 *
	 * @param Credential $credential Credential.
	 * @param int        $target_id  User being acted on.
	 * @return bool
	 */
	private static function may_manage_user( Credential $credential, $target_id ) {
		if ( $target_id === $credential->user_id ) {
			return false;
		}

		if ( ! $credential->limits_caps() ) {
			return true;
		}

		$target = get_userdata( $target_id );

		if ( ! $target ) {
			return true; // Nothing to escalate into; let core return its own not-found error.
		}

		if ( is_multisite() && is_super_admin( $target_id ) ) {
			return false;
		}

		foreach ( array_keys( array_filter( $target->allcaps ) ) as $cap ) {
			if ( ! $credential->allows_cap( $cap ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Hide roles a restricted credential couldn't exercise itself, so it can't create or promote
	 * a user into one. The REST users endpoint checks this list whenever a request sets `roles`.
	 *
	 * @param array $roles Editable roles, keyed by slug.
	 * @return array
	 */
	public static function editable_roles( $roles ) {
		$credential = self::for_user( get_current_user_id() );

		if ( ! $credential || ! $credential->limits_caps() ) {
			return $roles;
		}

		foreach ( $roles as $slug => $details ) {
			foreach ( array_keys( array_filter( $details['capabilities'] ) ) as $cap ) {
				if ( ! $credential->allows_cap( $cap ) ) {
					unset( $roles[ $slug ] );
					break;
				}
			}
		}

		return $roles;
	}

	/**
	 * A user created over REST without `roles` gets the site's `default_role`, which bypasses the
	 * `editable_roles` check. If that default is out of scope, create the user with no role
	 * instead. This filter can't return an error, so failing closed this way is the safe option.
	 *
	 * @param \stdClass $prepared_user User object about to be inserted.
	 * @return \stdClass
	 */
	public static function default_role_for_new_user( $prepared_user ) {
		$credential = self::for_user( get_current_user_id() );

		if ( ! $credential || ! $credential->limits_caps() ) {
			return $prepared_user;
		}

		if ( empty( $prepared_user->ID ) && ! isset( $prepared_user->role ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';

			if ( ! isset( get_editable_roles()[ get_option( 'default_role' ) ] ) ) {
				$prepared_user->role = '';
			}
		}

		return $prepared_user;
	}

	/**
	 * Request-level gates for read-only and abilities-only credentials.
	 *
	 * @param mixed            $result  Short-circuit result.
	 * @param \WP_REST_Server  $server  Server.
	 * @param \WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function rest_pre_dispatch( $result, $server, $request ) {
		if ( null !== $result ) {
			return $result;
		}

		return self::check_request( $request );
	}

	/**
	 * Final request gate, immediately before the route's permission callback and handler.
	 *
	 * @param mixed            $response Response so far; a WP_Error stops the request.
	 * @param array            $handler  Route handler.
	 * @param \WP_REST_Request $request  Request.
	 * @return mixed
	 */
	public static function rest_before_callbacks( $response, $handler, $request ) {
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$error = self::check_request( $request );

		return $error ? $error : $response;
	}

	/**
	 * Last line of defense: never return a response for an out-of-scope request, even if another
	 * filter replaced our error with one.
	 *
	 * @param \WP_HTTP_Response $response Response.
	 * @param \WP_REST_Server   $server   Server.
	 * @param \WP_REST_Request  $request  Request.
	 * @return \WP_HTTP_Response
	 */
	public static function rest_post_dispatch( $response, $server, $request ) {
		$error = self::check_request( $request );

		return $error ? rest_convert_error_to_response( $error ) : $response;
	}

	/**
	 * Apply read-only and abilities-only to a REST request.
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return WP_Error|null Error if the request is out of scope, otherwise null.
	 */
	private static function check_request( $request ) {
		$credential = self::for_user( get_current_user_id() );

		if ( ! $credential || ! $credential->scope ) {
			return null;
		}

		/**
		 * Filters whether a REST request is exempt from a credential's request-level gates.
		 *
		 * For routes that only let a credential see what it was granted or ask for more. Never
		 * exempt anything that could change what the credential may do. Capability checks still
		 * apply to exempt requests.
		 *
		 * @param bool             $exempt     Default false.
		 * @param \WP_REST_Request $request    Request.
		 * @param Credential       $credential Credential.
		 */
		if ( apply_filters( 'credential_scope_request_exempt', false, $request, $credential ) ) {
			return null;
		}

		if ( $credential->scope->restricts_to_abilities() && 0 !== strpos( untrailingslashit( $request->get_route() ) . '/', '/wp-abilities/v1/' ) ) {
			return self::error( __( 'These credentials may only use the Abilities API.', 'application-passwords-scoped' ) );
		}

		if ( $credential->scope->restricts_to_reads() && ! Request::is_read_only( $request ) ) {
			return self::error( __( 'These credentials are read-only.', 'application-passwords-scoped' ) );
		}

		return null;
	}

	/**
	 * Gate ability execution.
	 *
	 * @param bool|WP_Error $result  Permission result so far.
	 * @param string        $name    Ability name.
	 * @param mixed         $input   Input.
	 * @param \WP_Ability   $ability Ability.
	 * @return bool|WP_Error
	 */
	public static function ability_permission( $result, $name, $input, $ability ) {
		$credential = self::for_user( get_current_user_id() );

		if ( true !== $result || ! $credential || ! $credential->scope ) {
			return $result;
		}

		if ( ! $credential->scope->allows_ability( $name, $ability ) ) {
			return self::error(
				/* translators: %s: ability name. */
				sprintf( __( 'These credentials may not use the %s ability.', 'application-passwords-scoped' ), $name )
			);
		}

		return $result;
	}

	/**
	 * A granter is being deleted.
	 *
	 * @param int $granter_id User being deleted.
	 */
	public static function granter_deleted( $granter_id ) {
		self::maybe_revoke_granted( (int) $granter_id, 'deleted' );
	}

	/**
	 * A granter's roles changed. Only removals matter: a granter gaining a role can't loosen
	 * anything, because the owner's own capabilities still apply.
	 *
	 * @param int    $granter_id User whose role changed.
	 * @param string $role       New role (set_user_role) or removed role (remove_user_role).
	 * @param array  $old_roles  Previous roles (set_user_role only).
	 */
	public static function granter_role_changed( $granter_id, $role, $old_roles = null ) {
		if ( 'set_user_role' === current_action() && ( ! is_array( $old_roles ) || ! array_diff( $old_roles, array( $role ) ) ) ) {
			return;
		}

		self::maybe_revoke_granted( (int) $granter_id, 'demoted' );
	}

	/**
	 * Revoke the credentials someone issued for other users, if a filter says to.
	 *
	 * By default nothing is revoked. The credentials keep being capped at what the granter can do
	 * now: narrower after a demotion, and nothing at all once the granter is deleted. They fail
	 * closed either way, so revoking is a tidiness and visibility choice, not a security one.
	 *
	 * @param int    $granter_id Granter.
	 * @param string $reason     'deleted' or 'demoted'.
	 */
	private static function maybe_revoke_granted( $granter_id, $reason ) {
		foreach ( Credentials::granted_by( array( $granter_id ) ) as $row ) {
			if ( $row['user_id'] === $granter_id ) {
				continue;
			}

			/**
			 * Filters whether to revoke a credential someone issued for another user, when that
			 * person is deleted or loses a role.
			 *
			 * @param bool   $revoke     Whether to revoke. Default false.
			 * @param string $reason     'deleted' or 'demoted'.
			 * @param string $type       Credential type.
			 * @param int    $owner_id   User the credential belongs to.
			 * @param string $id         Credential identifier.
			 * @param int    $granter_id User who issued it.
			 */
			if ( apply_filters( 'credential_scope_revoke_granted', false, $reason, $row['type'], $row['user_id'], $row['id'], $granter_id ) ) {
				Credentials::revoke( $row['type'], $row['user_id'], $row['id'] );
			}
		}
	}

	/**
	 * Standard scope error.
	 *
	 * @param string $message Message.
	 * @return WP_Error
	 */
	private static function error( $message ) {
		return new WP_Error( 'credential_out_of_scope', $message, array( 'status' => 403 ) );
	}
}
