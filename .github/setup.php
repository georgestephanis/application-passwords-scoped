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

$demo_scopes = array(
	'Full access (unscoped)'  => array(),
	'Blog client'             => array(
		'role' => 'author',
		'deny' => array( 'publish' ),
	),
	'Read-only dashboard'     => array( 'read_only' => true ),
	'Site management, no PII' => array( 'deny' => array( 'users', 'data', 'code' ) ),
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
