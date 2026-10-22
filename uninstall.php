<?php
/**
 * Remove stored scopes. The passwords themselves belong to core and are left alone.
 *
 * Passwords suspended at deactivation stay suspended: their real hashes are deleted here, so they
 * can never work again unscoped. Their names say they're suspended, so owners can revoke them.
 *
 * @package Application_Passwords_Scoped
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_metadata( 'user', 0, '_application_password_scopes', '', true );
delete_metadata( 'user', 0, '_application_password_scopes_suspended', '', true );
