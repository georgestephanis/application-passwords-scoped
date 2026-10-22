<?php
/**
 * WP-CLI: `wp application-password scope <get|set|clear>`.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

use WP_CLI;

/**
 * Manage the scope of an Application Password.
 */
class CLI {

	/**
	 * Show a password's scope.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login, or email.
	 *
	 * <uuid>
	 * : Application Password UUID.
	 *
	 * [--format=<format>]
	 * : json or summary.
	 * ---
	 * default: json
	 * ---
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function get( $args, $assoc_args ) {
		list( $user_id, $uuid ) = $this->resolve( $args );
		$scope                  = Scope_Store::get( $user_id, $uuid );

		if ( 'summary' === ( $assoc_args['format'] ?? 'json' ) ) {
			WP_CLI::line( $scope->summary() );
		} else {
			WP_CLI::line( wp_json_encode( $scope->to_array(), JSON_PRETTY_PRINT ) );
		}
	}

	/**
	 * Set a password's scope. Replaces any existing scope.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login, or email.
	 *
	 * <uuid>
	 * : Application Password UUID.
	 *
	 * [--roles=<roles>]
	 * : Comma separated roles whose capabilities the password may use, e.g. `author,wpseo_manager`. Pass an empty string to allow no role capabilities.
	 *
	 * [--deny=<groups>]
	 * : Comma separated capability groups to withhold.
	 *
	 * [--read-only]
	 * : Only allow non-mutating requests.
	 *
	 * [--abilities=<names>]
	 * : Comma separated ability names (wildcards allowed) the password may execute. Pass an empty string to allow none.
	 *
	 * [--abilities-only]
	 * : Restrict REST access to the Abilities API.
	 *
	 * [--expires-in=<seconds>]
	 * : Stop the password working this many seconds from now.
	 *
	 * [--granted-by=<user-id>]
	 * : Also limit the password to what this user can do. The admin UI and REST API set this automatically when one user scopes another's password. Defaults to the existing granter; pass 0 to remove it.
	 *
	 * ## EXAMPLES
	 *
	 *     wp application-password scope set admin 3f2a... --roles=author,wpseo_manager --deny=plugins,users --expires-in=86400
	 *     wp application-password scope set admin 3f2a... --abilities-only --abilities='core/get-site-info,my-plugin/*'
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Assoc args.
	 */
	public function set( $args, $assoc_args ) {
		list( $user_id, $uuid ) = $this->resolve( $args );

		$scope = Scope::from_array(
			array(
				'roles'          => array_key_exists( 'roles', $assoc_args ) ? (string) $assoc_args['roles'] : null,
				'deny'           => $assoc_args['deny'] ?? array(),
				'read_only'      => ! empty( $assoc_args['read-only'] ),
				'abilities'      => array_key_exists( 'abilities', $assoc_args ) ? (string) $assoc_args['abilities'] : null,
				'abilities_only' => ! empty( $assoc_args['abilities-only'] ),
				'expires_in'     => (int) ( $assoc_args['expires-in'] ?? 0 ),
				// Keep an existing granter unless one is given: dropping it would silently loosen the scope.
				'granted_by'     => (int) ( $assoc_args['granted-by'] ?? Scope_Store::get( $user_id, $uuid )->granted_by ),
			)
		);

		if ( null !== $scope->roles ) {
			$unknown = array_diff( array_filter( array_map( 'trim', explode( ',', (string) $assoc_args['roles'] ) ) ), $scope->roles );
			if ( $unknown ) {
				WP_CLI::error( sprintf( 'Unknown role(s): %s', implode( ', ', $unknown ) ) );
			}
		}

		Scope_Store::set( $user_id, $uuid, $scope );
		WP_CLI::success( $scope->summary() );
	}

	/**
	 * Remove all restrictions from a password.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login, or email.
	 *
	 * <uuid>
	 * : Application Password UUID.
	 *
	 * @param array $args Positional args.
	 */
	public function clear( $args ) {
		list( $user_id, $uuid ) = $this->resolve( $args );

		Scope_Store::delete( $user_id, $uuid );
		WP_CLI::success( 'Scope cleared.' );
	}

	/**
	 * List capability groups.
	 *
	 * @subcommand groups
	 */
	public function groups() {
		$rows = array();
		foreach ( Capability_Groups::all() as $slug => $group ) {
			$rows[] = array(
				'group' => $slug,
				'label' => $group['label'],
				'caps'  => implode( ', ', $group['caps'] ),
			);
		}

		WP_CLI\Utils\format_items( 'table', $rows, array( 'group', 'label', 'caps' ) );
	}

	/**
	 * Resolve and validate the user/uuid args.
	 *
	 * @param array $args Positional args.
	 * @return array{0: int, 1: string}
	 */
	private function resolve( $args ) {
		$fetcher = new \WP_CLI\Fetchers\User();
		$user    = $fetcher->get_check( $args[0] );

		if ( ! \WP_Application_Passwords::get_user_application_password( $user->ID, $args[1] ) ) {
			WP_CLI::error( 'Application password not found.' );
		}

		return array( $user->ID, $args[1] );
	}
}
