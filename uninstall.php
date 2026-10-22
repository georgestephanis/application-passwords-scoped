<?php
/**
 * Remove stored scopes. The passwords themselves belong to core and are left alone.
 *
 * @package Application_Passwords_Scoped
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_metadata( 'user', 0, '_application_password_scopes', '', true );
