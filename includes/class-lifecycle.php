<?php
/**
 * Suspend scoped passwords while the plugin is inactive, so deactivating it can't unlock them.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

use WP_Application_Passwords;

/**
 * Core doesn't know about scopes, so with this plugin inactive a scoped password would quietly
 * regain its owner's full access (issue #13). Core also has no "disabled" flag on a password.
 *
 * So on deactivation, each scoped password's hash is moved into this plugin's own meta and
 * replaced with a value no password can match, and its name is marked as suspended. The password
 * then simply fails to authenticate. On activation, everything is put back exactly as it was:
 * nothing is deleted and no one has to reissue credentials.
 *
 * This covers deactivation, including network deactivation. It can't cover the plugin fataling or
 * its files disappearing; only core support can (#3, #13).
 */
class Lifecycle {

	/**
	 * User meta holding suspended passwords' real hashes and names, keyed by UUID.
	 */
	const SUSPENDED_META_KEY = '_application_password_scopes_suspended';

	/**
	 * Stored in place of the hash. Longer than 32 characters and without a known hash prefix, so
	 * core's check falls through to password_verify(), which is always false for a non-hash.
	 */
	const SENTINEL = '*application-passwords-scoped:suspended*';

	/**
	 * Restore suspended passwords.
	 */
	public static function activate() {
		foreach ( self::users_with( self::SUSPENDED_META_KEY ) as $user_id ) {
			$suspended = get_user_meta( $user_id, self::SUSPENDED_META_KEY, true );
			$passwords = WP_Application_Passwords::get_user_application_passwords( $user_id );

			if ( is_array( $suspended ) ) {
				foreach ( $passwords as $i => $item ) {
					$saved = $suspended[ $item['uuid'] ] ?? null;

					// Only restore an item still holding our sentinel; never overwrite a hash that
					// was changed some other way while the plugin was inactive.
					if ( $saved && self::SENTINEL === $item['password'] ) {
						$passwords[ $i ]['password'] = $saved['password'];
						$passwords[ $i ]['name']     = $saved['name'];
					}
				}

				self::save_passwords( $user_id, $passwords );
			}

			delete_user_meta( $user_id, self::SUSPENDED_META_KEY );
		}
	}

	/**
	 * Suspend every scoped password.
	 */
	public static function deactivate() {
		foreach ( self::users_with( Scope_Store::META_KEY ) as $user_id ) {
			$passwords = WP_Application_Passwords::get_user_application_passwords( $user_id );
			$suspended = get_user_meta( $user_id, self::SUSPENDED_META_KEY, true );
			$suspended = is_array( $suspended ) ? $suspended : array();
			$changed   = false;

			foreach ( $passwords as $i => $item ) {
				if ( self::SENTINEL === $item['password'] || ! Scope_Store::get( $user_id, $item['uuid'] )->is_restricted() ) {
					continue;
				}

				$suspended[ $item['uuid'] ] = array(
					'password' => $item['password'],
					'name'     => $item['name'],
				);

				$passwords[ $i ]['password'] = self::SENTINEL;
				$passwords[ $i ]['name']     = sprintf(
					/* translators: %s: application password name. */
					__( '%s (suspended: Scoped Application Passwords is inactive)', 'application-passwords-scoped' ),
					$item['name']
				);
				$changed = true;
			}

			if ( $changed ) {
				// Save our copy first: if the second write fails, the password still works, scoped,
				// rather than being lost.
				update_user_meta( $user_id, self::SUSPENDED_META_KEY, $suspended );
				self::save_passwords( $user_id, $passwords );
			}
		}
	}

	/**
	 * IDs of every user, network-wide, with a given meta key.
	 *
	 * @param string $meta_key Meta key.
	 * @return int[]
	 */
	private static function users_with( $meta_key ) {
		return array_map(
			'intval',
			get_users(
				array(
					'blog_id'  => 0,
					'meta_key' => $meta_key, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Runs only on (de)activation.
					'fields'   => 'ID',
				)
			)
		);
	}

	/**
	 * Write core's password list directly. WP_Application_Passwords::set_user_application_passwords()
	 * is protected, and update_application_password() can't change the hash.
	 *
	 * @param int   $user_id   User ID.
	 * @param array $passwords Items.
	 */
	private static function save_passwords( $user_id, array $passwords ) {
		update_user_meta( $user_id, WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, $passwords );
	}
}
