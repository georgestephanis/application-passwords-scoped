<?php
/**
 * Admin UI: scope controls on the profile screen and the Authorize Application screen.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

/**
 * Everything here rides on extension points core shipped in 5.6 for exactly this purpose:
 *
 * - `wp_create_application_password_form` / `wp_authorize_application_password_form` to render fields.
 * - JS filters `wp_application_passwords_new_password_request` and
 *   `wp_application_passwords_approve_app_request` to add `scope` to the REST request.
 * - `manage_application-passwords-user_columns` (+ `_custom_column` / `_custom_column_js_template`)
 *   to show the scope in the list table.
 */
class Admin {

	const FIELD = 'app_password_scope';

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'wp_create_application_password_form', array( __CLASS__, 'render_profile_fields' ) );
		add_action( 'wp_authorize_application_password_form', array( __CLASS__, 'render_authorize_fields' ), 10, 2 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'save_no_js' ), 10, 2 );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue' ) );

		add_filter( 'manage_application-passwords-user_columns', array( __CLASS__, 'columns' ) );
		add_action( 'manage_application-passwords-user_custom_column', array( __CLASS__, 'column' ), 10, 2 );
		add_action( 'manage_application-passwords-user_custom_column_js_template', array( __CLASS__, 'column_js_template' ) );
	}

	/**
	 * Enqueue assets on the two screens that create passwords.
	 *
	 * @param string $hook_suffix Screen hook.
	 */
	public static function enqueue( $hook_suffix ) {
		if ( ! in_array( $hook_suffix, array( 'profile.php', 'user-edit.php', 'authorize-application.php' ), true ) ) {
			return;
		}

		$url = plugin_dir_url( FILE ) . 'assets/';
		wp_enqueue_style( 'application-passwords-scoped', $url . 'admin.css', array(), VERSION );
		wp_enqueue_script( 'application-passwords-scoped', $url . 'admin.js', array( 'jquery', 'wp-hooks' ), VERSION, true );
	}

	/**
	 * Fields under "Add New Application Password" on the profile screen.
	 *
	 * @param \WP_User $user Profile user.
	 */
	public static function render_profile_fields( $user ) {
		self::render_fields( new Scope(), $user, false );
	}

	/**
	 * Fields on the Authorize Application screen.
	 *
	 * An app can *request* a scope by adding it to the authorize URL, e.g.
	 * `authorize-application.php?app_name=Foo&scope[roles][]=author&scope[deny]=plugins,users&scope[expires_in]=86400`.
	 * It's shown pre-filled; the person approving can tighten or loosen it before approving.
	 *
	 * @param array    $request Authorize request data.
	 * @param \WP_User $user    User.
	 */
	public static function render_authorize_fields( $request, $user ) {
		// Read-only prefill from the app's authorize URL; Scope::from_array() allowlists every field.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$requested = isset( $_REQUEST['scope'] ) ? Scope::from_array( wp_unslash( $_REQUEST['scope'] ) ) : new Scope();

		if ( $requested->is_restricted() ) {
			echo '<p class="app-password-scope-requested">';
			printf(
				/* translators: %s: summary of requested restrictions. */
				esc_html__( 'This application asked for limited access: %s', 'application-passwords-scoped' ),
				'<strong>' . esc_html( $requested->summary() ) . '</strong>'
			);
			echo '</p>';
		}

		self::render_fields( $requested, $user, true );
	}

	/**
	 * Shared field markup.
	 *
	 * @param Scope    $scope Initial values.
	 * @param \WP_User $user  User the password is for.
	 * @param bool     $open  Whether to expand the section initially.
	 */
	private static function render_fields( Scope $scope, $user, $open ) {
		$field     = self::FIELD;
		$names     = wp_roles()->get_names();
		$ladder    = Scope::hierarchical_roles();
		$own_core  = array_values( array_intersect( $ladder, (array) $user->roles ) );
		$acting    = wp_get_current_user();
		$for_other = $acting->ID !== $user->ID;

		// The highest selectable rung is the lower of the owner's and (when scoping someone
		// else's password) the acting user's. Anything above it is shown but disabled.
		$own_rank  = max( self::ladder_rank( $user, $ladder ), $for_other ? self::ladder_rank( $acting, $ladder ) : 0 );
		$extras    = array_values( array_diff( (array) $user->roles, $ladder ) );
		$abilities = function_exists( 'wp_get_abilities' ) ? wp_get_abilities() : array();

		// Map a stored/requested roles list back onto the two controls.
		$base_role = '';
		if ( null !== $scope->roles ) {
			$requested_core = array_values( array_intersect( $ladder, $scope->roles ) );
			$base_role      = $requested_core ? $requested_core[0] : '__none__';

			// A request for a role above the user's own is the same as no limit.
			if ( $requested_core && array_search( $base_role, $ladder, true ) < $own_rank ) {
				$base_role = '';
			}
		}

		// Snap a requested expiry to the closest preset at or below it, so the prefill never extends it.
		$expires_in = 0;
		if ( $scope->expires ) {
			foreach ( array_keys( self::expiry_options() ) as $seconds ) {
				if ( $seconds && $seconds <= $scope->expires - time() + MINUTE_IN_SECONDS ) {
					$expires_in = $seconds;
				}
			}
		}
		?>
		<details class="app-password-scope" data-own-roles="<?php echo esc_attr( wp_json_encode( $own_core ) ); ?>" <?php echo $open || $scope->is_restricted() ? 'open' : ''; ?>>
			<summary><?php esc_html_e( 'Limit what this password can do', 'application-passwords-scoped' ); ?></summary>

			<p class="description">
				<?php if ( $for_other ) : ?>
					<?php
					printf(
						/* translators: %s: display name of the user the password belongs to. */
						esc_html__( 'Restrictions only ever remove access. Because you are creating this for %s, it can never do more than either of you can.', 'application-passwords-scoped' ),
						esc_html( $user->display_name )
					);
					?>
				<?php else : ?>
					<?php esc_html_e( 'Restrictions only ever remove access. The password can never do more than your own account can.', 'application-passwords-scoped' ); ?>
				<?php endif; ?>
			</p>

			<fieldset>
				<legend><?php esc_html_e( 'Access level', 'application-passwords-scoped' ); ?></legend>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[read_only]" value="1" <?php checked( $scope->read_only ); ?> />
					<?php esc_html_e( 'Read-only — can view but not change anything', 'application-passwords-scoped' ); ?>
				</label>
			</fieldset>

			<fieldset class="app-password-scope-roles">
				<legend><?php esc_html_e( 'Act with at most the permissions of:', 'application-passwords-scoped' ); ?></legend>
				<label>
					<input type="radio" name="<?php echo esc_attr( $field ); ?>[base_role]" value="" <?php checked( $base_role, '' ); ?> />
					<?php
					if ( $for_other ) {
						/* translators: %s: display name of the user the password belongs to. */
						printf( esc_html__( "%s's own roles, capped at yours", 'application-passwords-scoped' ), esc_html( $user->display_name ) );
					} else {
						esc_html_e( 'My own role (no limit)', 'application-passwords-scoped' );
					}
					?>
				</label>
				<?php foreach ( $ladder as $rank => $slug ) : ?>
					<?php $above_own = $rank < $own_rank || ( $for_other && ! self::can_grant_role( $acting, $user, $slug ) ); ?>
					<label class="<?php echo $above_own ? 'is-disabled' : ''; ?>">
						<input type="radio" name="<?php echo esc_attr( $field ); ?>[base_role]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( $base_role, $slug ); ?> <?php disabled( $above_own ); ?> />
						<?php echo esc_html( translate_user_role( $names[ $slug ] ) ); ?>
						<?php if ( $above_own ) : ?>
							<span class="description"><?php echo $for_other ? esc_html__( '(not available to both of you)', 'application-passwords-scoped' ) : esc_html__( '(above your own role)', 'application-passwords-scoped' ); ?></span>
						<?php endif; ?>
					</label>
				<?php endforeach; ?>
				<label>
					<input type="radio" name="<?php echo esc_attr( $field ); ?>[base_role]" value="__none__" <?php checked( $base_role, '__none__' ); ?> />
					<?php esc_html_e( 'None of these', 'application-passwords-scoped' ); ?>
				</label>
				<?php if ( $extras ) : ?>
					<div class="app-password-scope-extra-roles">
						<p><?php esc_html_e( 'Also keep these roles:', 'application-passwords-scoped' ); ?></p>
						<?php foreach ( $extras as $slug ) : ?>
							<?php $grantable = ! $for_other || self::can_grant_role( $acting, $user, $slug ); ?>
							<label class="<?php echo $grantable ? '' : 'is-disabled'; ?>">
								<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[keep_roles][]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( $grantable && ( null === $scope->roles || in_array( $slug, $scope->roles, true ) ) ); ?> <?php disabled( ! $grantable ); ?> />
								<?php echo esc_html( translate_user_role( $names[ $slug ] ?? $slug ) ); ?>
								<?php if ( ! $grantable ) : ?>
									<span class="description"><?php esc_html_e( '(you don\'t have this role\'s permissions, so you can\'t grant it)', 'application-passwords-scoped' ); ?></span>
								<?php endif; ?>
							</label>
						<?php endforeach; ?>
					</div>
				<?php endif; ?>
			</fieldset>

			<fieldset>
				<label class="app-password-scope-expires">
					<?php esc_html_e( 'Stop working after:', 'application-passwords-scoped' ); ?>
					<select name="<?php echo esc_attr( $field ); ?>[expires_in]">
						<?php foreach ( self::expiry_options() as $seconds => $label ) : ?>
							<option value="<?php echo esc_attr( $seconds ); ?>" <?php selected( $expires_in, $seconds ); ?>><?php echo esc_html( $label ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
			</fieldset>

			<fieldset>
				<legend><?php esc_html_e( 'Never allow this password to:', 'application-passwords-scoped' ); ?></legend>
				<div class="app-password-scope-groups">
					<?php foreach ( Capability_Groups::all() as $slug => $group ) : ?>
						<label title="<?php echo esc_attr( $group['description'] ); ?>">
							<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[deny][]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, $scope->deny, true ) ); ?> />
							<?php echo esc_html( $group['label'] ); ?>
						</label>
					<?php endforeach; ?>
				</div>
			</fieldset>

			<fieldset>
				<legend><?php esc_html_e( 'Abilities', 'application-passwords-scoped' ); ?></legend>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[abilities_only]" value="1" <?php checked( $scope->abilities_only ); ?> />
					<?php esc_html_e( 'Only allow access through the Abilities API (recommended for AI agents)', 'application-passwords-scoped' ); ?>
				</label>
				<label>
					<input type="checkbox" class="app-password-scope-restrict-abilities" name="<?php echo esc_attr( $field ); ?>[restrict_abilities]" value="1" <?php checked( null !== $scope->abilities ); ?> />
					<?php esc_html_e( 'Only allow these abilities:', 'application-passwords-scoped' ); ?>
				</label>
				<div class="app-password-scope-abilities">
					<?php if ( $abilities ) : ?>
						<?php foreach ( $abilities as $ability ) : ?>
							<label title="<?php echo esc_attr( $ability->get_description() ); ?>">
								<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[abilities][]" value="<?php echo esc_attr( $ability->get_name() ); ?>" <?php checked( null !== $scope->abilities && $scope->allows_ability( $ability->get_name() ) ); ?> />
								<?php echo esc_html( $ability->get_label() ); ?> <code><?php echo esc_html( $ability->get_name() ); ?></code>
							</label>
						<?php endforeach; ?>
					<?php else : ?>
						<p class="description"><?php esc_html_e( 'No abilities are registered on this site.', 'application-passwords-scoped' ); ?></p>
					<?php endif; ?>
				</div>
			</fieldset>
		</details>
		<?php
	}

	/**
	 * Position of a user's highest core role on the ladder (0 = top). Super admins rank above all.
	 *
	 * @param \WP_User $user   User.
	 * @param string[] $ladder Hierarchical role slugs, highest first.
	 * @return int
	 */
	private static function ladder_rank( $user, array $ladder ) {
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return 0;
		}

		foreach ( $ladder as $rank => $slug ) {
			if ( in_array( $slug, (array) $user->roles, true ) ) {
				return $rank;
			}
		}

		return count( $ladder );
	}

	/**
	 * Whether a granter could hand a role's powers to the owner: every capability of the role that
	 * the owner can actually exercise, the granter must be able to exercise too. Mirrors the runtime
	 * rule (Scope::allows_cap() intersects with the granter), so the UI never offers a choice the
	 * enforcement would silently undo.
	 *
	 * Capabilities neither user can use (e.g. `unfiltered_html` under DISALLOW_UNFILTERED_HTML)
	 * are ignored, otherwise no role containing one could ever be granted.
	 *
	 * @param \WP_User $granter User creating/scoping the password.
	 * @param \WP_User $owner   User the password belongs to.
	 * @param string   $slug    Role slug.
	 * @return bool
	 */
	private static function can_grant_role( $granter, $owner, $slug ) {
		$role = get_role( $slug );

		if ( ! $role ) {
			return false;
		}

		foreach ( array_keys( array_filter( $role->capabilities ) ) as $cap ) {
			if ( user_can( $owner, $cap ) && ! user_can( $granter, $cap ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Expiry presets, in seconds from now.
	 *
	 * @return array<int, string>
	 */
	private static function expiry_options() {
		return array(
			0                    => __( 'Never', 'application-passwords-scoped' ),
			HOUR_IN_SECONDS      => __( '1 hour', 'application-passwords-scoped' ),
			DAY_IN_SECONDS       => __( '1 day', 'application-passwords-scoped' ),
			WEEK_IN_SECONDS      => __( '1 week', 'application-passwords-scoped' ),
			MONTH_IN_SECONDS     => __( '30 days', 'application-passwords-scoped' ),
			3 * MONTH_IN_SECONDS => __( '90 days', 'application-passwords-scoped' ),
			YEAR_IN_SECONDS      => __( '1 year', 'application-passwords-scoped' ),
		);
	}

	/**
	 * Without JS, the Authorize Application form posts to authorize-application.php, which
	 * verifies its own nonce and then calls create_new_application_password(). Pick up the
	 * scope fields at that point.
	 *
	 * @param int   $user_id User ID.
	 * @param array $item    New item.
	 */
	public static function save_no_js( $user_id, $item ) {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Core verified the `authorize_application_password` nonce before creating the password.
		if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}

		if ( ! isset( $_POST['action'], $_POST[ self::FIELD ] ) || 'authorize_application_password' !== $_POST['action'] ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Scope::from_array() allowlists every field.
		$data               = self::normalize_form( wp_unslash( $_POST[ self::FIELD ] ), get_userdata( $user_id ) );
		$data['granted_by'] = get_current_user_id() === $user_id ? 0 : get_current_user_id();
		Scope_Store::set( $user_id, $item['uuid'], Scope::from_array( $data ) );
		// phpcs:enable
	}

	/**
	 * Translate form fields into Scope input.
	 *
	 * - `base_role` (the ladder dropdown) plus `keep_roles` (toggles for the user's other roles)
	 *   become `roles`. Leaving the dropdown alone with every toggle on means no role limit.
	 * - A `restrict_abilities` toggle distinguishes "no ability restriction" (null) from
	 *   "no abilities allowed" (empty list).
	 *
	 * assets/admin.js mirrors this for the JS/REST path; keep the two in step.
	 *
	 * @param array    $data Raw form data.
	 * @param \WP_User $user User the password is for.
	 * @return array
	 */
	private static function normalize_form( $data, $user ) {
		$data   = (array) $data;
		$ladder = Scope::hierarchical_roles();
		$extras = array_values( array_diff( (array) $user->roles, $ladder ) );
		$base   = isset( $data['base_role'] ) ? (string) $data['base_role'] : '';
		$kept   = array_values( array_intersect( $extras, (array) ( $data['keep_roles'] ?? array() ) ) );

		if ( '' === $base && count( $kept ) === count( $extras ) ) {
			$data['roles'] = null;
		} else {
			if ( '' === $base ) {
				$base_roles = array_values( array_intersect( $ladder, (array) $user->roles ) );
			} else {
				$base_roles = '__none__' === $base ? array() : array( $base );
			}
			$data['roles'] = array_merge( $base_roles, $kept );
		}
		unset( $data['role'] );

		if ( empty( $data['restrict_abilities'] ) ) {
			$data['abilities'] = null;
		} elseif ( ! isset( $data['abilities'] ) ) {
			$data['abilities'] = array();
		}

		return $data;
	}

	/**
	 * Add a Scope column.
	 *
	 * @param array $columns Columns.
	 * @return array
	 */
	public static function columns( $columns ) {
		$columns['scope'] = __( 'Access', 'application-passwords-scoped' );

		return $columns;
	}

	/**
	 * Render the Scope column.
	 *
	 * @param string $column Column name.
	 * @param array  $item   Application Password item.
	 */
	public static function column( $column, $item ) {
		if ( 'scope' !== $column ) {
			return;
		}

		// The list table only runs on the profile screens; the user ID comes from the screen.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : get_current_user_id();

		echo esc_html( Scope_Store::get( $user_id, $item['uuid'] )->summary() );
	}

	/**
	 * JS template for rows added without a reload (data is the REST response).
	 *
	 * @param string $column Column name.
	 */
	public static function column_js_template( $column ) {
		if ( 'scope' === $column ) {
			echo '{{ data.scope ? data.scope.summary : "" }}';
		}
	}
}
