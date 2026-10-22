<?php
/**
 * WordPress Playground demo setup.
 *
 * Creates one example password per kind of scope for the admin user, so the profile screen's
 * list table shows what each looks like. Loaded by the runPHP step in blueprint.json.
 *
 * @package Application_Passwords_Scoped
 */

use Application_Passwords_Scoped\Scope;
use Application_Passwords_Scoped\Scope_Store;

require_once '/wordpress/wp-load.php';

// A closure keeps the demo's variables out of the global scope.
( static function () {
	$admin = get_user_by( 'login', 'admin' );

	// Stand-ins for plugin roles held alongside a core role, like Yoast's SEO Manager or bbPress's
	// Keymaster. They show up on the scope form as independent "keep this role" toggles.
	add_role(
		'seo_manager',
		'SEO Manager (demo)',
		array(
			'read'       => true,
			'manage_seo' => true,
		)
	);
	add_role(
		'forum_moderator',
		'Forum Moderator (demo)',
		array(
			'read'            => true,
			'moderate_forums' => true,
		)
	);
	$admin->add_role( 'seo_manager' );
	$admin->add_role( 'forum_moderator' );

	$scopes = array(
		'Full access (unscoped)'  => array(),
		'Blog client'             => array(
			'roles' => array( 'author' ),
			'deny'  => array( 'publish' ),
		),
		'Read-only dashboard'     => array( 'read_only' => true ),
		'Site management, no PII' => array( 'deny' => array( 'users', 'data', 'code' ) ),
		'SEO tool'                => array( 'roles' => array( 'editor', 'seo_manager' ) ),
		'AI agent'                => array(
			'abilities_only' => true,
			'abilities'      => array( 'core/get-site-info' ),
			'expires_in'     => WEEK_IN_SECONDS,
		),
	);

	foreach ( $scopes as $name => $scope ) {
		$created = WP_Application_Passwords::create_new_application_password( $admin->ID, array( 'name' => $name ) );
		if ( is_wp_error( $created ) ) {
			continue;
		}
		Scope_Store::set( $admin->ID, $created[1]['uuid'], Scope::from_array( $scope ) );
	}
} )();
