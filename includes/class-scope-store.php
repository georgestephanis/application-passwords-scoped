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
