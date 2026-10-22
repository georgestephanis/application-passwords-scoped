<?php
/**
 * Applies the active Application Password's scope to the current request.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

use WP_Error;

/**
 * Enforcement happens at three layers:
 *
 * 1. Capabilities (`map_meta_cap`): every capability check for the authenticated user is reduced
 *    to its primitive caps, and if any of them falls outside the scope the check gets
 *    `do_not_allow`. This is the backbone — it covers REST, XML-RPC, Abilities, and any plugin
 *    code that calls `current_user_can()`, and `do_not_allow` beats even multisite super admins.
 * 2. Requests (`rest_pre_dispatch`): coarse gates that aren't expressible as capabilities —
 *    read-only (HTTP method) and abilities-only (route namespace). Runs per sub-request in
 *    `/batch/v1` too.
 * 3. Abilities (`wp_ability_permission_result`): an allowlist of ability names, and read-only
 *    passwords may only run abilities annotated `readonly`.
 */
class Enforcer {

	/**
	 * Meta capabilities a scoped password can never use, because they would let it mint or
	 * widen credentials and escape its own scope.
	 */
	const ESCALATION_CAPS = array(
		'create_app_password',
		'edit_app_password',
		'delete_app_password',
		'delete_app_passwords',
	);

	/**
	 * Meta capabilities that act on another user account. A scoped password can't use them on its
	 * own account, or on any account that can do more than the scope allows. Otherwise it could
	 * reset that account's password or email and log in as it, escaping the scope.
	 */
	const USER_CAPS = array( 'edit_user', 'delete_user', 'remove_user', 'promote_user' );

	/**
	 * Active scope, if the current request authenticated with a restricted Application Password.
	 *
	 * @var Scope|null
	 */
	private static $scope = null;

	/**
	 * User the active scope applies to.
	 *
	 * @var int
	 */
	private static $user_id = 0;

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'application_password_did_authenticate', array( __CLASS__, 'activate' ), 10, 2 );
		add_action( 'wp_authenticate_application_password_errors', array( __CLASS__, 'validate' ), 10, 3 );
		add_filter( 'site_option_site_admins', array( __CLASS__, 'filter_super_admins' ) );
		add_filter( 'map_meta_cap', array( __CLASS__, 'map_meta_cap' ), PHP_INT_MAX, 4 );
		add_filter( 'editable_roles', array( __CLASS__, 'editable_roles' ), PHP_INT_MAX );
		add_filter( 'rest_pre_insert_user', array( __CLASS__, 'default_role_for_new_user' ), PHP_INT_MAX );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'rest_pre_dispatch' ), 10, 3 );
		add_filter( 'wp_ability_permission_result', array( __CLASS__, 'ability_permission' ), 10, 4 );
		add_action( 'wp_delete_application_password', array( __CLASS__, 'cleanup' ), 10, 2 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'record_granter' ), 10, 2 );
	}

	/**
	 * Remember the scope of the password that just authenticated.
	 *
	 * @param \WP_User $user User.
	 * @param array    $item Application Password item.
	 */
	public static function activate( $user, $item ) {
		$scope = Scope_Store::get( $user->ID, $item['uuid'] );

		/**
		 * Filters the scope applied to an authenticated Application Password.
		 *
		 * @param Scope    $scope Scope.
		 * @param \WP_User $user  User.
		 * @param array    $item  Application Password item.
		 */
		$scope = apply_filters( 'application_password_scope', $scope, $user, $item );

		if ( $scope instanceof Scope && $scope->is_restricted() ) {
			self::$scope   = $scope;
			self::$user_id = (int) $user->ID;
		}
	}

	/**
	 * Get the scope in effect for the current request, if any.
	 *
	 * @return Scope|null
	 */
	public static function active_scope() {
		return self::$scope;
	}

	/**
	 * Reset state. For tests.
	 */
	public static function reset() {
		self::$scope   = null;
		self::$user_id = 0;
	}

	/**
	 * Reject a password at authentication time if its scope can't be honored.
	 *
	 * - Expired passwords fail like a wrong password would. Checking here, lazily, means no cron
	 *   job is needed and a missed cron can't leave a password alive.
	 * - XML-RPC has no per-method read/write metadata and isn't part of the Abilities API, so
	 *   request-level restrictions can't be enforced there. Refuse rather than silently ignore
	 *   them. Role ceilings and denied groups are pure capability rules and work over XML-RPC.
	 *
	 * @param WP_Error $error Error object to add to.
	 * @param \WP_User $user  User.
	 * @param array    $item  Matched Application Password item.
	 */
	public static function validate( $error, $user, $item ) {
		$scope = Scope_Store::get( $user->ID, $item['uuid'] );

		if ( $scope->is_expired() ) {
			$error->add(
				'application_password_expired',
				__( 'This application password has expired.', 'application-passwords-scoped' )
			);
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST
			&& ( $scope->read_only || $scope->abilities_only || null !== $scope->abilities ) ) {
			$error->add(
				'application_password_scope_xmlrpc',
				__( 'This application password is restricted to the REST API.', 'application-passwords-scoped' )
			);
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
		if ( ! self::$scope || ! self::$scope->limits_caps() || ! is_array( $super_admins ) ) {
			return $super_admins;
		}

		$user = get_userdata( self::$user_id );

		if ( $user ) {
			$super_admins = array_values( array_diff( $super_admins, array( $user->user_login ) ) );
		}

		return $super_admins;
	}

	/**
	 * Reduce capability checks to what the scope allows.
	 *
	 * @param string[] $caps    Primitive caps required.
	 * @param string   $cap     Capability being checked.
	 * @param int      $user_id User being checked.
	 * @param array    $args    Extra args (e.g. object ID).
	 * @return string[]
	 */
	public static function map_meta_cap( $caps, $cap, $user_id, $args ) {
		if ( ! self::$scope || (int) $user_id !== self::$user_id ) {
			return $caps;
		}

		if ( in_array( $cap, self::ESCALATION_CAPS, true ) ) {
			return array( 'do_not_allow' );
		}

		if ( in_array( $cap, self::USER_CAPS, true ) && isset( $args[0] ) && ! self::may_manage_user( (int) $args[0] ) ) {
			return array( 'do_not_allow' );
		}

		foreach ( $caps as $primitive ) {
			if ( ! self::$scope->allows_cap( $primitive ) ) {
				return array( 'do_not_allow' );
			}
		}

		return $caps;
	}

	/**
	 * Whether the active scoped password may act on another user account.
	 *
	 * Never its own account. For others, only when the scope limits no capabilities, or the target
	 * can do nothing the scope forbids. A password scoped to Author can still edit a Subscriber's
	 * profile, if the user could, but not an Editor's.
	 *
	 * @param int $target_id User being acted on.
	 * @return bool
	 */
	private static function may_manage_user( $target_id ) {
		if ( $target_id === self::$user_id ) {
			return false;
		}

		if ( ! self::$scope->limits_caps() ) {
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
			if ( ! self::$scope->allows_cap( $cap ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Hide roles a scoped password couldn't exercise itself, so it can't create or promote a user
	 * into one. The REST users endpoint checks this list whenever a request sets `roles`.
	 *
	 * @param array $roles Editable roles, keyed by slug.
	 * @return array
	 */
	public static function editable_roles( $roles ) {
		if ( ! self::$scope || ! self::$scope->limits_caps() || get_current_user_id() !== self::$user_id ) {
			return $roles;
		}

		foreach ( $roles as $slug => $details ) {
			foreach ( array_keys( array_filter( $details['capabilities'] ) ) as $cap ) {
				if ( ! self::$scope->allows_cap( $cap ) ) {
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
		if ( ! self::$scope || ! self::$scope->limits_caps() || get_current_user_id() !== self::$user_id ) {
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
	 * Request-level gates for read-only and abilities-only passwords.
	 *
	 * @param mixed            $result  Short-circuit result.
	 * @param \WP_REST_Server  $server  Server.
	 * @param \WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function rest_pre_dispatch( $result, $server, $request ) {
		if ( null !== $result || ! self::$scope || get_current_user_id() !== self::$user_id ) {
			return $result;
		}

		$route  = untrailingslashit( $request->get_route() );
		$method = $request->get_method();

		// Always let a password introspect itself so the client can discover what it was granted.
		if ( 'GET' === $method && preg_match( '#^/wp/v2/users/(me|\d+)/application-passwords/introspect$#', $route ) ) {
			return $result;
		}

		if ( self::$scope->abilities_only && 0 !== strpos( $route . '/', '/wp-abilities/v1/' ) ) {
			return self::error( __( 'This application password may only use the Abilities API.', 'application-passwords-scoped' ) );
		}

		if ( self::$scope->read_only && ! in_array( $method, array( 'GET', 'HEAD', 'OPTIONS' ), true ) ) {
			return self::error( __( 'This application password is read-only.', 'application-passwords-scoped' ) );
		}

		return $result;
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
		if ( true !== $result || ! self::$scope || get_current_user_id() !== self::$user_id ) {
			return $result;
		}

		if ( ! self::$scope->allows_ability( $name, $ability ) ) {
			return self::error(
				/* translators: %s: ability name. */
				sprintf( __( 'This application password is not allowed to use the %s ability.', 'application-passwords-scoped' ), $name )
			);
		}

		return $result;
	}

	/**
	 * When one user creates a password for another, cap it at what the creator can do — even if
	 * the request set no scope at all. Without this, an admin with `edit_users` but no
	 * `install_plugins` (say, on multisite) could mint a plugin-installing password for a
	 * super admin. A scope sent in the same REST request is saved after this and keeps the granter.
	 *
	 * @param int   $user_id User the password belongs to.
	 * @param array $item    New item.
	 */
	public static function record_granter( $user_id, $item ) {
		$acting = get_current_user_id();

		if ( ! $acting || $acting === (int) $user_id ) {
			return;
		}

		$scope             = Scope_Store::get( $user_id, $item['uuid'] );
		$scope->granted_by = $acting;
		Scope_Store::set( $user_id, $item['uuid'], $scope );
	}

	/**
	 * Delete a scope when its password is deleted.
	 *
	 * @param int   $user_id User ID.
	 * @param array $item    Deleted item.
	 */
	public static function cleanup( $user_id, $item ) {
		Scope_Store::delete( $user_id, $item['uuid'] );
	}

	/**
	 * Standard scope error.
	 *
	 * @param string $message Message.
	 * @return WP_Error
	 */
	private static function error( $message ) {
		return new WP_Error( 'application_password_out_of_scope', $message, array( 'status' => 403 ) );
	}
}
