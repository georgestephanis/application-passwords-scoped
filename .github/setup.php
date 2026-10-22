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

$demo_admin = get_user_by( 'login', 'admin' );

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
$demo_admin->add_role( 'seo_manager' );
$demo_admin->add_role( 'forum_moderator' );

$demo_scopes = array(
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

foreach ( $demo_scopes as $demo_name => $demo_scope ) {
	$demo_created = WP_Application_Passwords::create_new_application_password( $demo_admin->ID, array( 'name' => $demo_name ) );
	if ( is_wp_error( $demo_created ) ) {
		continue;
	}
	Scope_Store::set( $demo_admin->ID, $demo_created[1]['uuid'], Scope::from_array( $demo_scope ) );
}
