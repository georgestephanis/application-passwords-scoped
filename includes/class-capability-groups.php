<?php
/**
 * Named groups of primitive capabilities that can be withheld from an Application Password.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

/**
 * Capability groups.
 *
 * Granting/withholding individual primitive capabilities is too fine-grained to present to a
 * person approving an app, so they are bundled into "classes" of permissions. The list is
 * filterable so plugins can add their own groups (e.g. WooCommerce could add "shop_manage").
 */
class Capability_Groups {

	/**
	 * Get all groups.
	 *
	 * @return array<string, array{label: string, description: string, caps: string[]}>
	 */
	public static function all() {
		$groups = array(
			'users'    => array(
				'label'       => __( 'Manage users', 'application-passwords-scoped' ),
				'description' => __( 'Create, edit, delete, and change the role of users.', 'application-passwords-scoped' ),
				'caps'        => array( 'list_users', 'create_users', 'add_users', 'edit_users', 'delete_users', 'remove_users', 'promote_users', 'manage_network_users' ),
			),
			'plugins'  => array(
				'label'       => __( 'Manage plugins', 'application-passwords-scoped' ),
				'description' => __( 'Install, activate, update, edit, and delete plugins.', 'application-passwords-scoped' ),
				'caps'        => array( 'activate_plugins', 'install_plugins', 'update_plugins', 'delete_plugins', 'edit_plugins', 'resume_plugins', 'manage_network_plugins' ),
			),
			'themes'   => array(
				'label'       => __( 'Manage themes & appearance', 'application-passwords-scoped' ),
				'description' => __( 'Switch, install, edit, and customize themes, menus, widgets, and global styles.', 'application-passwords-scoped' ),
				'caps'        => array( 'switch_themes', 'install_themes', 'update_themes', 'delete_themes', 'edit_themes', 'resume_themes', 'edit_theme_options', 'customize', 'manage_network_themes' ),
			),
			'settings' => array(
				'label'       => __( 'Change site settings', 'application-passwords-scoped' ),
				'description' => __( 'Modify options, privacy settings, and network settings.', 'application-passwords-scoped' ),
				'caps'        => array( 'manage_options', 'manage_privacy_options', 'manage_network_options', 'manage_network', 'manage_sites', 'create_sites', 'delete_sites' ),
			),
			'core'     => array(
				'label'       => __( 'Update WordPress', 'application-passwords-scoped' ),
				'description' => __( 'Update core and install or update translations.', 'application-passwords-scoped' ),
				'caps'        => array( 'update_core', 'install_languages', 'update_languages' ),
			),
			'code'     => array(
				'label'       => __( 'Unfiltered code & files', 'application-passwords-scoped' ),
				'description' => __( 'Post unfiltered HTML/JS, upload any file type, and edit files on the server.', 'application-passwords-scoped' ),
				'caps'        => array( 'unfiltered_html', 'unfiltered_upload', 'edit_files', 'edit_plugins', 'edit_themes' ),
			),
			'publish'  => array(
				'label'       => __( 'Publish content', 'application-passwords-scoped' ),
				'description' => __( 'Make posts and pages public. Drafts can still be written.', 'application-passwords-scoped' ),
				'caps'        => array( 'publish_posts', 'publish_pages' ),
			),
			'delete'   => array(
				'label'       => __( 'Delete content', 'application-passwords-scoped' ),
				'description' => __( 'Trash or delete posts and pages.', 'application-passwords-scoped' ),
				'caps'        => array( 'delete_posts', 'delete_others_posts', 'delete_published_posts', 'delete_private_posts', 'delete_pages', 'delete_others_pages', 'delete_published_pages', 'delete_private_pages' ),
			),
			'others'   => array(
				'label'       => __( "Edit others' content", 'application-passwords-scoped' ),
				'description' => __( 'Edit or delete posts and pages written by other users.', 'application-passwords-scoped' ),
				'caps'        => array( 'edit_others_posts', 'edit_others_pages', 'delete_others_posts', 'delete_others_pages' ),
			),
			'uploads'  => array(
				'label'       => __( 'Upload media', 'application-passwords-scoped' ),
				'description' => __( 'Add files to the media library.', 'application-passwords-scoped' ),
				'caps'        => array( 'upload_files' ),
			),
			'comments' => array(
				'label'       => __( 'Moderate comments', 'application-passwords-scoped' ),
				'description' => __( 'Approve, edit, spam, and delete comments.', 'application-passwords-scoped' ),
				'caps'        => array( 'moderate_comments' ),
			),
			'data'     => array(
				'label'       => __( 'Import, export & personal data', 'application-passwords-scoped' ),
				'description' => __( 'Bulk import/export site content and export or erase personal data.', 'application-passwords-scoped' ),
				'caps'        => array( 'import', 'export', 'export_others_personal_data', 'erase_others_personal_data' ),
			),
		);

		/**
		 * Filters the capability groups that can be withheld from a scoped Application Password.
		 *
		 * Caps may be wildcard patterns (`manage_shop_*`). See also Capability_Groups::register().
		 *
		 * @param array $groups Map of group slug => { label, description, caps[] }.
		 */
		return apply_filters( 'application_password_scope_capability_groups', array_merge( $groups, self::$registered ) );
	}

	/**
	 * Groups registered with register(), merged into all() before the filter runs.
	 *
	 * @var array<string, array>
	 */
	private static $registered = array();

	/**
	 * Register a capability group. Call on or before `init`; the group then appears on the scope
	 * form and in the REST schema. Equivalent to filtering application_password_scope_capability_groups.
	 *
	 * `caps` may contain wildcard patterns, e.g. `manage_woocommerce*` or `*_shop_order*`, so a group
	 * keeps covering capabilities a plugin adds later.
	 *
	 * @param string $slug Group slug: lowercase letters, numbers, `_` and `-`.
	 * @param array  $args { label: string, description: string, caps: string[] }.
	 * @return bool False if the slug or args are invalid.
	 */
	public static function register( $slug, array $args ) {
		if ( ! preg_match( '/^[a-z0-9_-]+$/', $slug ) || empty( $args['label'] ) || empty( $args['caps'] ) ) {
			return false;
		}

		self::$registered[ $slug ] = array(
			'label'       => (string) $args['label'],
			'description' => (string) ( $args['description'] ?? '' ),
			'caps'        => array_values( array_map( 'strval', (array) $args['caps'] ) ),
		);

		return true;
	}

	/**
	 * Split a list of group slugs into exact capability names and wildcard patterns.
	 *
	 * @param string[] $slugs Group slugs.
	 * @return array{caps: array<string, true>, patterns: string[]}
	 */
	public static function caps_for( array $slugs ) {
		$groups   = self::all();
		$caps     = array();
		$patterns = array();

		foreach ( $slugs as $slug ) {
			if ( isset( $groups[ $slug ] ) ) {
				foreach ( $groups[ $slug ]['caps'] as $cap ) {
					if ( false !== strpbrk( $cap, '*?[' ) ) {
						$patterns[] = $cap;
					} else {
						$caps[ $cap ] = true;
					}
				}
			}
		}

		return array(
			'caps'     => $caps,
			'patterns' => array_values( array_unique( $patterns ) ),
		);
	}

	/**
	 * Whether a capability is covered by a caps_for() result.
	 *
	 * @param string $cap     Capability.
	 * @param array  $covered caps_for() result.
	 * @return bool
	 */
	public static function covers( $cap, array $covered ) {
		if ( isset( $covered['caps'][ $cap ] ) ) {
			return true;
		}

		foreach ( $covered['patterns'] as $pattern ) {
			if ( fnmatch( $pattern, $cap, FNM_NOESCAPE ) ) {
				return true;
			}
		}

		return false;
	}
}
