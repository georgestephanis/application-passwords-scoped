<?php
/**
 * Plugin Name:       Scoped Application Passwords
 * Plugin URI:        https://github.com/georgestephanis/application-passwords-scoped
 * Description:       Exploration: restrict what an individual Application Password can do — cap it at a lower role, strip classes of capabilities, make it read-only, or limit it to specific Abilities.
 * Version:           0.1.0
 * Requires at least: 6.9
 * Requires PHP:      7.4
 * Author:            George Stephanis
 * License:           GPL-2.0-or-later
 * Text Domain:       application-passwords-scoped
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

defined( 'ABSPATH' ) || exit;

const VERSION = '0.1.0';
const FILE    = __FILE__;

require_once __DIR__ . '/includes/class-capability-groups.php';
require_once __DIR__ . '/includes/class-scope.php';
require_once __DIR__ . '/includes/class-scope-store.php';
require_once __DIR__ . '/includes/class-enforcer.php';
require_once __DIR__ . '/includes/class-rest.php';
require_once __DIR__ . '/includes/class-admin.php';

Enforcer::init();
REST::init();
Admin::init();

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once __DIR__ . '/includes/class-cli.php';
	\WP_CLI::add_command( 'application-password scope', __NAMESPACE__ . '\\CLI' );
}
