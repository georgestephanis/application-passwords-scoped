<?php
/**
 * Test-only mu-plugin for tests/smoke.sh. Never ship this.
 *
 * GET /?aps_fixture=1 creates one Application Password per scope under test for `admin` and
 * returns { name: password } as JSON.
 *
 * @package Application_Passwords_Scoped
 */

use Application_Passwords_Scoped\Scope;
use Application_Passwords_Scoped\Scope_Store;

// Playground serves over plain HTTP without WP_ENVIRONMENT_TYPE=local, so core disables
// Application Passwords. Defining that constant via the blueprint breaks Playground's redirects.
add_filter( 'wp_is_application_passwords_available', '__return_true' );

// GET /wp-json/aps-test/v1/can/<cap> → { "can": bool } for the authenticated user.
add_action(
	'rest_api_init',
	static function () {
		register_rest_route(
			'aps-test/v1',
			'/search',
			array(
				'methods'             => 'POST',
				'permission_callback' => 'is_user_logged_in',
				'callback'            => '__return_empty_array',
			)
		);
		register_rest_route(
			'aps-test/v1',
			'/can/(?P<cap>[a-z_]+)',
			array(
				'methods'             => 'GET',
				'permission_callback' => '__return_true',
				'callback'            => static function ( $request ) {
					return array( 'can' => current_user_can( $request['cap'] ) );
				},
			)
		);
	}
);

// A plugin-registered capability group with a wildcard (#10).
add_action(
	'init',
	static function () {
		if ( class_exists( 'Application_Passwords_Scoped\Capability_Groups' ) ) {
			Application_Passwords_Scoped\Capability_Groups::register(
				'seo',
				array(
					'label' => 'SEO',
					'caps'  => array( 'manage_seo*' ),
				)
			);
		}
	},
	0
);

// GET /?aps_decide=<uuid>&decision=approve|deny: decide an access request as admin (#8).
add_action(
	'init',
	static function () {
		if ( empty( $_GET['aps_decide'] ) ) {
			return;
		}
		wp_set_current_user( 1 );
		$scope = Application_Passwords_Scoped\Access_Requests::decide( 1, sanitize_text_field( wp_unslash( $_GET['aps_decide'] ) ), sanitize_key( $_GET['decision'] ?? 'deny' ) );
		wp_send_json( array( 'scope' => $scope ? $scope->to_array() : null ) );
	},
	1
);

// GET /?aps_revoke_test=0|1: an admin creates a password for Eddie, is deleted, and we report
// whether the password survived, with the revoke filter off or on (#12).
add_action(
	'init',
	static function () {
		if ( ! isset( $_GET['aps_revoke_test'] ) ) {
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/user.php';
		$revoke  = (bool) $_GET['aps_revoke_test'];
		$granter = wp_insert_user(
			array(
				'user_login' => 'granter' . wp_generate_password( 4, false, false ),
				'user_pass'  => wp_generate_password(),
				'role'       => 'administrator',
			)
		);
		$eddie   = get_user_by( 'login', 'eddie' );
		wp_set_current_user( $granter );
		$created = WP_Application_Passwords::create_new_application_password( $eddie->ID, array( 'name' => 'granted-' . wp_generate_password( 4, false ) ) );
		wp_set_current_user( 1 );
		add_filter( 'application_password_scope_revoke_granted', $revoke ? '__return_true' : '__return_false' );
		wp_delete_user( $granter );
		wp_send_json( array( 'survived' => (bool) WP_Application_Passwords::get_user_application_password( $eddie->ID, $created[1]['uuid'] ) ) );
	},
	1
);

// GET /?aps_toggle=activate|deactivate runs the plugin's real (de)activation hooks (issue #13).
add_action(
	'init',
	static function () {
		if ( empty( $_GET['aps_toggle'] ) ) {
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugin  = 'application-passwords-scoped/application-passwords-scoped.php';
		$network = is_multisite() && ! empty( $_GET['network'] );
		if ( $network ) {
			wp_set_current_user( 1 ); // Network activation needs a super admin.
			update_site_option( 'site_admins', array( 'admin' ) );
		}
		if ( 'deactivate' === $_GET['aps_toggle'] ) {
			deactivate_plugins( $plugin, false, $network );
		} else {
			activate_plugin( $plugin, '', $network );
		}
		wp_send_json( array( 'active' => is_plugin_active( $plugin ) ) );
	},
	1
);

// A GraphQL-style endpoint outside REST: POST /?aps_graphql=1 with {"query":"..."}. Queries read;
// mutations write. Plus a REST search route that reads despite using POST.
add_filter(
	'application_password_is_api_request',
	static function ( $is_api ) {
		return $is_api || isset( $_GET['aps_graphql'] );
	}
);
add_filter(
	'application_password_scope_request_is_read_only',
	static function ( $is_read_only, $request ) {
		if ( null === $request && isset( $_GET['aps_graphql'] ) ) {
			$body = json_decode( (string) file_get_contents( 'php://input' ), true );
			return 0 !== strpos( ltrim( (string) ( $body['query'] ?? '' ) ), 'mutation' );
		}
		if ( $request && '/aps-test/v1/search' === $request->get_route() ) {
			return true;
		}
		return $is_read_only;
	},
	10,
	2
);
add_action(
	'template_redirect',
	static function () {
		if ( isset( $_GET['aps_graphql'] ) ) {
			wp_send_json( array( 'user' => get_current_user_id() ) );
		}
	}
);

// Bypass probes for issue #14.

// 1. Another plugin short-circuits a route from rest_pre_dispatch, at an early priority, and
// (badly) ignores any result an earlier filter already returned.
add_filter(
	'rest_pre_dispatch',
	static function ( $result, $server, $request ) {
		if ( '/aps-test/v1/short-circuit' === $request->get_route() ) {
			return new WP_REST_Response( array( 'short_circuited' => true ) );
		}
		return $result;
	},
	-1000,
	3
);

// 2. A plugin endpoint outside REST that opts into app-password auth.
// GET /?aps_custom=<cap> → { "user": id, "can": bool }.
add_filter(
	'application_password_is_api_request',
	static function ( $is_api ) {
		return $is_api || isset( $_GET['aps_custom'] ) || false !== strpos( $_SERVER['REQUEST_URI'] ?? '', '/wp-json/aps-test/' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Test fixture.
	}
);
add_action(
	'template_redirect',
	static function () {
		if ( isset( $_GET['aps_custom'] ) ) {
			wp_send_json(
				array(
					'user' => get_current_user_id(),
					'can'  => current_user_can( sanitize_key( $_GET['aps_custom'] ) ),
				)
			);
		}
	}
);

// 3. Something resolves the current user on a REST URL before core defines REST_REQUEST.
add_action(
	'init',
	static function () {
		if ( false !== strpos( $_SERVER['REQUEST_URI'] ?? '', '/wp-json/aps-test/' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- Test fixture.
			get_current_user_id();
		}
	},
	0
);

add_action(
	'init',
	static function () {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Test fixture.
		if ( empty( $_GET['aps_fixture'] ) ) {
			return;
		}

		$admin = get_user_by( 'login', 'admin' );
		$out   = array();

		// Plugin-style roles held alongside Administrator (cf. Yoast SEO Manager, bbPress Keymaster).
		add_role(
			'seo_manager',
			'SEO Manager',
			array(
				'read'       => true,
				'manage_seo' => true,
			)
		);
		add_role(
			'forum_moderator',
			'Forum Moderator',
			array(
				'read'            => true,
				'moderate_forums' => true,
			)
		);
		$admin->add_role( 'seo_manager' );
		$admin->add_role( 'forum_moderator' );

		// An Editor who also holds SEO Manager, for granter tests.
		$eddie = get_user_by( 'login', 'eddie' );
		if ( ! $eddie ) {
			$eddie = get_userdata(
				wp_insert_user(
					array(
						'user_login' => 'eddie',
						'user_pass'  => wp_generate_password(),
						'user_email' => 'eddie@example.test',
						'role'       => 'editor',
					)
				)
			);
		}
		$eddie->add_role( 'seo_manager' );

		// A role only Eddie holds, so admin can't grant its capability.
		add_role( 'newsletter_editor', 'Newsletter Editor', array( 'manage_newsletter' => true ) );
		$eddie->add_role( 'newsletter_editor' );
		$out['eddie_id'] = $eddie->ID;

		// Targets for "act through another account" tests: a second admin and a subscriber.
		foreach ( array(
			'ada' => 'administrator',
			'sam' => 'subscriber',
		) as $login => $role ) {
			$target = get_user_by( 'login', $login );
			if ( ! $target ) {
				$target = get_userdata(
					wp_insert_user(
						array(
							'user_login' => $login,
							'user_pass'  => wp_generate_password(),
							'user_email' => $login . '@example.test',
							'role'       => $role,
						)
					)
				);
			}
			$out[ $login . '_id' ] = $target->ID;
		}

		// An out-of-scope default role, to test users created without `roles`.
		update_option( 'default_role', 'editor' );

		$defs = array(
			'full'      => array(),
			'author'    => array( 'role' => 'author' ), // Legacy single-role shorthand.
			'dropforum' => array( 'roles' => array( 'administrator', 'seo_manager' ) ),
			'seoonly'   => array( 'roles' => array( 'seo_manager' ) ),
			'noroles'   => array( 'roles' => array() ),
			'nopublish' => array( 'deny' => array( 'publish' ) ),
			'granted'   => array( 'granted_by' => $eddie->ID ), // Admin's password, capped at Eddie.
			'noxmlrpc'  => array( 'block_xmlrpc' => true ),
			'noseo'     => array( 'deny' => array( 'seo' ) ), // Registered below, with a wildcard.
			'asker'     => array(
				'abilities_only' => true,
				'abilities'      => array( 'core/get-site-info' ),
			),
			'editme'    => array( 'read_only' => true ),
			'noplugins' => array( 'deny' => array( 'plugins', 'users' ) ),
			'readonly'  => array( 'read_only' => true ),
			'abilities' => array(
				'abilities_only' => true,
				'abilities'      => array( 'core/get-site-info' ),
			),
			'expired'   => array( 'expires' => time() - 10 ),
			'expiring'  => array( 'expires_in' => HOUR_IN_SECONDS ),
		);

		foreach ( $defs as $name => $scope ) {
			$created = WP_Application_Passwords::create_new_application_password( $admin->ID, array( 'name' => $name . '-' . wp_generate_password( 6, false ) ) );
			Scope_Store::set( $admin->ID, $created[1]['uuid'], Scope::from_array( $scope ) );
			$out[ $name ]           = $created[0];
			$out[ $name . '_uuid' ] = $created[1]['uuid'];
		}

		// A password created with no scope, while a site default applies (#11).
		$default = static function () {
			return array( 'read_only' => true );
		};
		add_filter( 'application_password_scope_default', $default );
		$created = WP_Application_Passwords::create_new_application_password( $admin->ID, array( 'name' => 'defaulted-' . wp_generate_password( 6, false ) ) );
		remove_filter( 'application_password_scope_default', $default );
		$out['defaulted'] = $created[0];

		wp_send_json( $out );
	}
);
