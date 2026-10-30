<?php
/**
 * Connects Application Passwords to the shared Credential Scope ceiling.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

use Credential_Scope\Credential;
use Credential_Scope\Credentials;

/**
 * Application Passwords are one credential type among many as far as enforcement goes: this
 * class turns an authenticated password into a Credential and hands it to the Credential Scope
 * layer (includes/credential-scope/), which applies the ceiling. What stays here is what only
 * makes sense for Application Passwords: blocking XML-RPC, recording the granter when a password
 * is created, the routes a scoped password may always use, and cleanup when one is deleted.
 */
class Enforcer {

	/**
	 * Credential type name.
	 */
	const TYPE = 'application_password';

	/**
	 * Meta capabilities that manage Application Passwords. No restricted credential, of any type,
	 * may use them: it could mint an unscoped sibling or rewrite its own scope.
	 */
	const ESCALATION_CAPS = array(
		'create_app_password',
		'edit_app_password',
		'delete_app_password',
		'delete_app_passwords',
	);

	/**
	 * Register hooks.
	 */
	public static function init() {
		Credentials::register_type(
			self::TYPE,
			array(
				'escalation_caps' => self::ESCALATION_CAPS,
				'granted_by'      => array( __CLASS__, 'granted_by' ),
				'revoke'          => array( '\WP_Application_Passwords', 'delete_application_password' ),
			)
		);

		add_action( 'application_password_did_authenticate', array( __CLASS__, 'activate' ), 10, 2 );
		add_action( 'wp_authenticate_application_password_errors', array( __CLASS__, 'validate' ), 10, 3 );
		add_filter( 'credential_scope_request_exempt', array( __CLASS__, 'request_exempt' ), 10, 3 );
		add_filter( 'credential_scope_request_is_read_only', array( __CLASS__, 'legacy_is_read_only' ), 10, 3 );
		add_filter( 'credential_scope_revoke_granted', array( __CLASS__, 'legacy_revoke_granted' ), 10, 6 );
		add_action( 'wp_delete_application_password', array( __CLASS__, 'cleanup' ), 10, 2 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'record_granter' ), 10, 2 );
	}

	/**
	 * Describe an Application Password as a Credential.
	 *
	 * @param \WP_User $user User.
	 * @param array    $item Application Password item.
	 * @return Credential
	 */
	public static function credential( $user, $item ) {
		$scope = Scope_Store::get( $user->ID, $item['uuid'] );

		/**
		 * Filters the scope applied to an authenticated Application Password.
		 *
		 * @param Scope    $scope Scope.
		 * @param \WP_User $user  User.
		 * @param array    $item  Application Password item.
		 */
		$scope = apply_filters( 'application_password_scope', $scope, $user, $item );
		$scope = $scope instanceof Scope ? $scope : new Scope();

		return new Credential( self::TYPE, $item['uuid'], $user->ID, $scope, $scope->granted_by, $scope->expires );
	}

	/**
	 * Hand the password that just authenticated to the ceiling.
	 *
	 * @param \WP_User $user User.
	 * @param array    $item Application Password item.
	 */
	public static function activate( $user, $item ) {
		Credentials::set_current( self::credential( $user, $item ) );
	}

	/**
	 * Get the scope in effect for the current request, if a restricted password authenticated.
	 *
	 * @return Scope|null
	 */
	public static function active_scope() {
		$credential = Credentials::current();

		return $credential && self::TYPE === $credential->type ? $credential->scope : null;
	}

	/**
	 * Reject a password at authentication time if its scope can't be honored.
	 *
	 * Expiry and REST-only rules are shared with every credential type (Credentials::validate()).
	 * Checking here, lazily, means no cron job is needed and a missed cron can't leave a password
	 * alive. This runs per XML-RPC call, because XML-RPC authenticates inside each method, after
	 * the method name is known, so read-only passwords can still use read methods there.
	 *
	 * Blocking XML-RPC outright is Application Password specific: no other credential works there.
	 *
	 * @param \WP_Error $error Error object to add to.
	 * @param \WP_User  $user  User.
	 * @param array     $item  Matched Application Password item.
	 */
	public static function validate( $error, $user, $item ) {
		$credential = self::credential( $user, $item );

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && $credential->scope->block_xmlrpc ) {
			$error->add(
				'application_password_scope_no_xmlrpc',
				__( 'This application password may not be used with XML-RPC.', 'application-passwords-scoped' )
			);
			return;
		}

		$error->merge_from( Credentials::validate( $credential ) );
	}

	/**
	 * Always let a password see what it was granted, and ask for more (Access_Requests). Neither
	 * can change what the password may do; only the owner approving a request can.
	 *
	 * @param bool             $exempt     Exempt so far.
	 * @param \WP_REST_Request $request    Request.
	 * @param Credential       $credential Credential.
	 * @return bool
	 */
	public static function request_exempt( $exempt, $request, $credential ) {
		if ( $exempt || self::TYPE !== $credential->type ) {
			return $exempt;
		}

		$route  = untrailingslashit( $request->get_route() );
		$method = $request->get_method();

		if ( 'GET' === $method && preg_match( '#^/wp/v2/users/(me|\d+)/application-passwords/introspect$#', $route ) ) {
			return true;
		}

		return 0 === strpos( $route . '/', '/' . Access_Requests::NAMESPACE . '/access-requests/' ) && in_array( $method, array( 'GET', 'POST' ), true );
	}

	/**
	 * Keep the original read-only filter working on top of the shared one.
	 *
	 * @param bool                  $is_read_only  Decision so far.
	 * @param \WP_REST_Request|null $request       REST request, or null off REST.
	 * @param string|null           $xmlrpc_method XML-RPC method, if any.
	 * @return bool
	 */
	public static function legacy_is_read_only( $is_read_only, $request, $xmlrpc_method ) {
		/**
		 * Filters whether a request only reads. Prefer `credential_scope_request_is_read_only`,
		 * which this wraps; it applies to every credential type.
		 *
		 * @param bool                  $is_read_only  Default decision.
		 * @param \WP_REST_Request|null $request       REST request, or null for a non-REST endpoint.
		 * @param string|null           $xmlrpc_method XML-RPC method being called, if any.
		 */
		return (bool) apply_filters( 'application_password_scope_request_is_read_only', $is_read_only, $request, $xmlrpc_method );
	}

	/**
	 * Keep the original revoke filter working on top of the shared one.
	 *
	 * @param bool   $revoke     Decision so far.
	 * @param string $reason     'deleted' or 'demoted'.
	 * @param string $type       Credential type.
	 * @param int    $owner_id   Owner.
	 * @param string $uuid       Credential identifier.
	 * @param int    $granter_id Granter.
	 * @return bool
	 */
	public static function legacy_revoke_granted( $revoke, $reason, $type, $owner_id, $uuid, $granter_id ) {
		if ( self::TYPE !== $type ) {
			return $revoke;
		}

		/**
		 * Filters whether to revoke a password someone created for another user, when that
		 * person is deleted or loses a role. Prefer `credential_scope_revoke_granted`, which this
		 * wraps; it applies to every credential type.
		 *
		 * @param bool   $revoke     Whether to revoke. Default false.
		 * @param string $reason     'deleted' or 'demoted'.
		 * @param int    $owner_id   User the password belongs to.
		 * @param string $uuid       Application Password UUID.
		 * @param int    $granter_id User who created it.
		 */
		return (bool) apply_filters( 'application_password_scope_revoke_granted', $revoke, $reason, $owner_id, $uuid, $granter_id );
	}

	/**
	 * Passwords some users created for someone else, for the shared granter cascade.
	 *
	 * @param int[] $granter_ids Granters.
	 * @return array<int, array{user_id: int, id: string, granted_by: int}>
	 */
	public static function granted_by( array $granter_ids ) {
		$rows = array();

		foreach ( Scope_Store::granted_by( $granter_ids ) as $row ) {
			$rows[] = array(
				'user_id'    => $row['user_id'],
				'id'         => $row['uuid'],
				'granted_by' => $row['granted_by'],
			);
		}

		return $rows;
	}

	/**
	 * Apply the default scope to every new password, and cap it at its creator when one user
	 * creates a password for another — even if the request set no scope at all.
	 *
	 * The default is full access (#11). A scope sent with the same REST request is saved after this
	 * and replaces the default, keeping the granter. People narrow from whatever the default is. Without this, an admin with `edit_users` but no
	 * `install_plugins` (say, on multisite) could mint a plugin-installing password for a
	 * super admin. A scope sent in the same REST request is saved after this and keeps the granter.
	 *
	 * @param int   $user_id User the password belongs to.
	 * @param array $item    New item.
	 */
	public static function record_granter( $user_id, $item ) {
		$acting = get_current_user_id();
		$scope  = Scope::default_for( (int) $user_id );

		if ( $acting && $acting !== (int) $user_id ) {
			$scope->granted_by = $acting;
		}

		if ( $scope->is_restricted() ) {
			Scope_Store::set( $user_id, $item['uuid'], $scope );
		}
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
}
