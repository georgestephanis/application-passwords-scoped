<?php
/**
 * Persistence for scopes.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

/**
 * Scopes live in their own user meta row keyed by the password's UUID, rather than inside core's
 * `_application_passwords` array. Core rewrites that array on update/usage-tracking and only
 * round-trips the keys it knows about, so piggy-backing on it would be fragile. If this moved
 * into core, a `scope` key on the item itself would be the natural home.
 */
class Scope_Store {

	const META_KEY = '_application_password_scopes';

	/**
	 * Get the scope for a password. Always returns a Scope (unrestricted if none stored).
	 *
	 * @param int    $user_id User ID.
	 * @param string $uuid    Application Password UUID.
	 * @return Scope
	 */
	public static function get( $user_id, $uuid ) {
		$all = self::all( $user_id );

		return Scope::from_array( $all[ $uuid ] ?? null );
	}

	/**
	 * Save (or clear, if unrestricted) the scope for a password.
	 *
	 * @param int    $user_id User ID.
	 * @param string $uuid    Application Password UUID.
	 * @param Scope  $scope   Scope.
	 * @return bool
	 */
	public static function set( $user_id, $uuid, Scope $scope ) {
		$all = self::all( $user_id );

		if ( $scope->is_restricted() ) {
			$all[ $uuid ] = $scope->to_array();
		} else {
			unset( $all[ $uuid ] );
		}

		return self::save( $user_id, $all );
	}

	/**
	 * Save a scope submitted by the current user: the one path for REST, forms and approvals.
	 *
	 * The granter is never taken from input. If someone other than the owner is acting, they become
	 * the granter. If the owner is acting, an existing granter is kept: an admin's cap on a password
	 * they set up for someone doesn't vanish because its owner edited the scope.
	 *
	 * @param int    $user_id Owner.
	 * @param string $uuid    Application Password UUID.
	 * @param mixed  $data    Untrusted scope data.
	 * @return Scope The scope as saved.
	 */
	public static function save_from_request( $user_id, $uuid, $data ) {
		$data   = is_array( $data ) ? $data : array();
		$acting = get_current_user_id();

		$data['granted_by'] = $acting && $acting !== (int) $user_id
			? $acting
			: self::get( $user_id, $uuid )->granted_by;

		$scope = Scope::from_array( $data );
		self::set( $user_id, $uuid, $scope );

		/**
		 * Fires after a scope is saved from a request, form or approval.
		 *
		 * @param Scope  $scope   Saved scope.
		 * @param int    $user_id Owner.
		 * @param string $uuid    Application Password UUID.
		 * @param int    $acting  User who saved it.
		 */
		do_action( 'application_password_scope_saved', $scope, (int) $user_id, $uuid, $acting );

		return $scope;
	}

	/**
	 * Remove the scope for a password.
	 *
	 * @param int    $user_id User ID.
	 * @param string $uuid    Application Password UUID.
	 * @return bool
	 */
	public static function delete( $user_id, $uuid ) {
		$all = self::all( $user_id );
		unset( $all[ $uuid ] );

		return self::save( $user_id, $all );
	}

	/**
	 * Passwords, belonging to anyone, that were granted by any of the given users.
	 *
	 * @param int[] $granter_ids User IDs.
	 * @return array<int, array{user_id: int, uuid: string, granted_by: int}>
	 */
	public static function granted_by( array $granter_ids ) {
		$granter_ids = array_map( 'intval', $granter_ids );
		$found       = array();
		$owners      = get_users(
			array(
				'blog_id'  => 0,
				'meta_key' => self::META_KEY, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Only on the delete-user screen.
				'fields'   => 'ID',
			)
		);

		foreach ( $owners as $owner_id ) {
			foreach ( self::all( (int) $owner_id ) as $uuid => $data ) {
				$granter = (int) ( $data['granted_by'] ?? 0 );
				if ( in_array( $granter, $granter_ids, true ) ) {
					$found[] = array(
						'user_id'    => (int) $owner_id,
						'uuid'       => $uuid,
						'granted_by' => $granter,
					);
				}
			}
		}

		return $found;
	}

	/**
	 * Raw stored scopes for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array<string, array>
	 */
	private static function all( $user_id ) {
		$all = get_user_meta( $user_id, self::META_KEY, true );

		return is_array( $all ) ? $all : array();
	}

	/**
	 * Write scopes, deleting the meta row when empty.
	 *
	 * @param int   $user_id User ID.
	 * @param array $all     Scopes keyed by UUID.
	 * @return bool
	 */
	private static function save( $user_id, array $all ) {
		if ( ! $all ) {
			return (bool) delete_user_meta( $user_id, self::META_KEY );
		}

		return (bool) update_user_meta( $user_id, self::META_KEY, $all );
	}
}
