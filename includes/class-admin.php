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

		add_action( 'after_plugin_row_' . plugin_basename( FILE ), array( __CLASS__, 'deactivation_warning' ), 10, 0 );
		add_action( 'delete_user_form', array( __CLASS__, 'delete_user_warning' ), 10, 2 );
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
		wp_enqueue_script( 'application-passwords-scoped', $url . 'admin.js', array( 'jquery', 'wp-hooks', 'wp-api-fetch', 'wp-i18n' ), VERSION, true );
		wp_set_script_translations( 'application-passwords-scoped', 'application-passwords-scoped' );
	}

	/**
	 * Fields under "Add New Application Password" on the profile screen.
	 *
	 * @param \WP_User $user Profile user.
	 */
	public static function render_profile_fields( $user ) {
		self::render_fields( Scope::default_for( $user->ID ), $user );
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
				esc_html__( 'This application asked for limited access: %s. You can limit it further, but not give it more. If it needs more later, it can ask, and you will be able to approve or deny that.', 'application-passwords-scoped' ),
				'<strong>' . esc_html( $requested->summary() ) . '</strong>'
			);
			echo '</p>';
		}

		self::render_fields(
			$requested,
			$user,
			array(
				'open'  => true,
				'limit' => $requested->is_restricted() ? $requested : null,
			)
		);

		if ( $requested->is_restricted() ) {
			// For the no-JS path; save_no_js() narrows the submission to this. Disabled inputs
			// aren't posted, so locked restrictions would otherwise be lost.
			printf( '<input type="hidden" name="%s" value="%s" />', esc_attr( self::FIELD . '_requested' ), esc_attr( wp_json_encode( $requested->to_array() ) ) );
		}
	}

	/**
	 * Shared field markup for the create, authorize and edit forms.
	 *
	 * @param Scope    $scope Initial values.
	 * @param \WP_User $user  User the password is for.
	 * @param array    $args  {
	 *     Optional. Rendering options.
	 *
	 *     @type bool       $open  Expand the section initially. Default: when $scope is restricted.
	 *     @type Scope|null $limit Narrowing-only mode: anything looser than this is locked or hidden.
	 *     @type string     $field Input name prefix; must be unique per form on the page.
	 *     @type string     $class Extra class on the root element.
	 * }.
	 */
	private static function render_fields( Scope $scope, $user, array $args = array() ) {
		$args      = wp_parse_args(
			$args,
			array(
				'open'  => false,
				'limit' => null,
				'field' => self::FIELD,
				'class' => '',
			)
		);
		$limit     = $args['limit'];
		$field     = $args['field'];
		$names     = wp_roles()->get_names();
		$ladder    = Scope::hierarchical_roles();
		$own_core  = array_values( array_intersect( $ladder, (array) $user->roles ) );
		$acting    = wp_get_current_user();
		$for_other = $acting->ID !== $user->ID;

		// The highest selectable rung is the lowest of the owner's, the acting user's (when scoping
		// someone else's password) and the limit's. Anything above it is shown but disabled.
		$own_rank   = max( self::ladder_rank( $user, $ladder ), $for_other ? self::ladder_rank( $acting, $ladder ) : 0 );
		$limit_rank = 0;
		if ( $limit && null !== $limit->roles ) {
			$limit_core = array_values( array_intersect( $ladder, $limit->roles ) );
			$limit_rank = $limit_core ? (int) array_search( $limit_core[0], $ladder, true ) : count( $ladder );
		}
		$extras    = array_values( array_diff( (array) $user->roles, $ladder ) );
		$abilities = function_exists( 'wp_get_abilities' ) ? wp_get_abilities() : array();

		// Map a stored/requested roles list back onto the two controls.
		$base_role = '';
		if ( null !== $scope->roles ) {
			$requested_core = array_values( array_intersect( $ladder, $scope->roles ) );
			$base_role      = $requested_core ? $requested_core[0] : '__none__';

			// A request for a role above the user's own is the same as no limit.
			if ( $requested_core && array_search( $base_role, $ladder, true ) < $own_rank && ! $limit ) {
				$base_role = '';
			}
		}

		// Editing keeps the current expiry unless it's changed. Elsewhere, snap a requested expiry
		// to the closest preset at or below it, so the prefill never extends it.
		$keep_expiry = $scope->expires && ! $limit && 'app-password-scope-edit' === $args['class'];
		$max_expiry  = $limit && $limit->expires ? $limit->expires - time() + MINUTE_IN_SECONDS : 0;
		$expires_in  = $keep_expiry ? 'keep' : 0;
		if ( $scope->expires && ! $keep_expiry ) {
			foreach ( array_keys( self::expiry_options() ) as $seconds ) {
				if ( $seconds && $seconds <= $scope->expires - time() + MINUTE_IN_SECONDS ) {
					$expires_in = $seconds;
				}
			}
		}

		?>
		<details class="app-password-scope <?php echo esc_attr( $args['class'] ); ?>" data-own-roles="<?php echo esc_attr( wp_json_encode( $own_core ) ); ?>" <?php echo $args['open'] || $scope->is_restricted() ? 'open' : ''; ?>>
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
					<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[read_only]" value="1" <?php echo $limit && $limit->read_only ? 'checked disabled' : checked( $scope->read_only, true, false ); ?> />
					<?php esc_html_e( 'Read-only — can view but not change anything', 'application-passwords-scoped' ); ?>
				</label>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[block_xmlrpc]" value="1" <?php echo $limit && $limit->block_xmlrpc ? 'checked disabled' : checked( $scope->block_xmlrpc, true, false ); ?> />
					<?php esc_html_e( 'Block XML-RPC — allow only the REST API and other modern endpoints', 'application-passwords-scoped' ); ?>
				</label>
			</fieldset>

			<fieldset class="app-password-scope-roles">
				<legend><?php esc_html_e( 'Act with at most the permissions of:', 'application-passwords-scoped' ); ?></legend>
				<label <?php echo $limit_rank ? 'hidden' : ''; ?>>
					<input type="radio" name="<?php echo esc_attr( $field ); ?>[base_role]" value="" <?php checked( $base_role, '' ); ?> <?php disabled( (bool) $limit_rank ); ?> />
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
					<?php
					$above_own   = $rank < $own_rank || ( $for_other && ! self::can_grant_role( $acting, $user, $slug ) );
					$above_limit = $rank < $limit_rank;
					if ( $above_limit && ! $above_own ) {
						continue; // Narrowing only: don't offer roles above what the app asked for.
					}
					?>
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
							<?php
							if ( $limit && null !== $limit->roles && ! in_array( $slug, $limit->roles, true ) ) {
								continue; // Narrowing only.
							}
							$grantable = ! $for_other || self::can_grant_role( $acting, $user, $slug );
							?>
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
					<select name="<?php echo esc_attr( $field ); ?>[expires_in]" data-expires="<?php echo (int) $scope->expires; ?>">
						<?php if ( $keep_expiry ) : ?>
							<option value="keep" selected>
								<?php
								/* translators: %s: date and time. */
								printf( esc_html__( 'Unchanged (%s)', 'application-passwords-scoped' ), esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $scope->expires ) ) );
								?>
							</option>
						<?php endif; ?>
						<?php foreach ( self::expiry_options() as $seconds => $label ) : ?>
							<?php
							if ( $max_expiry && ( ! $seconds || $seconds > $max_expiry ) ) {
								continue; // Narrowing only.
							}
							?>
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
							<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[deny][]" value="<?php echo esc_attr( $slug ); ?>" <?php echo $limit && in_array( $slug, $limit->deny, true ) ? 'checked disabled' : checked( in_array( $slug, $scope->deny, true ), true, false ); ?> />
							<?php echo esc_html( $group['label'] ); ?>
						</label>
					<?php endforeach; ?>
				</div>
			</fieldset>

			<fieldset>
				<legend><?php esc_html_e( 'Abilities', 'application-passwords-scoped' ); ?></legend>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[abilities_only]" value="1" <?php echo $limit && $limit->abilities_only ? 'checked disabled' : checked( $scope->abilities_only, true, false ); ?> />
					<?php esc_html_e( 'Only allow access through the Abilities API (recommended for AI agents)', 'application-passwords-scoped' ); ?>
				</label>
				<label>
					<input type="checkbox" class="app-password-scope-restrict-abilities" name="<?php echo esc_attr( $field ); ?>[restrict_abilities]" value="1" <?php echo $limit && null !== $limit->abilities ? 'checked disabled' : checked( null !== $scope->abilities, true, false ); ?> />
					<?php esc_html_e( 'Only allow these abilities:', 'application-passwords-scoped' ); ?>
				</label>
				<div class="app-password-scope-abilities">
					<?php if ( $abilities ) : ?>
						<?php foreach ( $abilities as $ability ) : ?>
							<?php
							if ( $limit && ! $limit->lists_ability( $ability->get_name() ) ) {
								continue; // Narrowing only.
							}
							?>
							<label title="<?php echo esc_attr( $ability->get_description() ); ?>">
								<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[abilities][]" value="<?php echo esc_attr( $ability->get_name() ); ?>" <?php checked( null !== $scope->abilities && $scope->lists_ability( $ability->get_name() ) ); ?> />
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
		$data = self::normalize_form( wp_unslash( $_POST[ self::FIELD ] ), get_userdata( $user_id ) );

		// Narrowing only: never save more than the app asked for.
		if ( isset( $_POST[ self::FIELD . '_requested' ] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Decoded, then allowlisted by Scope::from_array().
			$requested = Scope::from_array( json_decode( wp_unslash( $_POST[ self::FIELD . '_requested' ] ), true ) );
			$data      = Scope::from_array( $data )->constrain_to( $requested )->to_array();
		}

		Scope_Store::save_from_request( $user_id, $item['uuid'], $data );
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

		if ( isset( $data['expires_in'] ) && 'keep' === $data['expires_in'] ) {
			unset( $data['expires_in'] );
		}

		if ( empty( $data['restrict_abilities'] ) ) {
			$data['abilities'] = null;
		} elseif ( ! isset( $data['abilities'] ) ) {
			$data['abilities'] = array();
		}

		return $data;
	}

	/**
	 * Tell people on the Plugins screen what deactivating does to scoped passwords (see Lifecycle,
	 * issue #13): they stop working until the plugin is reactivated.
	 */
	public static function deactivation_warning() {
		if ( ! is_plugin_active( plugin_basename( FILE ) ) ) {
			return;
		}

		$query = new \WP_User_Query(
			array(
				'blog_id'     => 0,
				'meta_key'    => Scope_Store::META_KEY, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Plugins screen only.
				'fields'      => 'ID',
				'number'      => 1,
				'count_total' => true,
			)
		);
		$count = $query->get_total();

		if ( ! $count ) {
			return;
		}

		$columns = _get_list_table( 'WP_Plugins_List_Table' )->get_column_count();
		?>
		<tr class="plugin-update-tr active">
			<td colspan="<?php echo (int) $columns; ?>" class="plugin-update colspanchange">
				<div class="notice inline notice-warning notice-alt">
					<p>
						<?php
						printf(
							/* translators: %s: number of users. */
							esc_html( _n( '%s user has scoped application passwords. Deactivating this plugin suspends them: they stop working until it is reactivated. Clear their restrictions first if you want them to keep working with full access.', '%s users have scoped application passwords. Deactivating this plugin suspends them: they stop working until it is reactivated. Clear their restrictions first if you want them to keep working with full access.', $count, 'application-passwords-scoped' ) ),
							esc_html( number_format_i18n( $count ) )
						);
						?>
					</p>
				</div>
			</td>
		</tr>
		<?php
	}

	/**
	 * On the delete-user confirmation screen, list other users' passwords that the users being
	 * deleted granted. Those passwords fail closed once their granter is gone (issue #12), which
	 * could break an integration without warning.
	 *
	 * @param \WP_User $current_user User doing the deleting.
	 * @param int[]    $user_ids     Users being deleted.
	 */
	public static function delete_user_warning( $current_user, $user_ids ) {
		$affected = array_values(
			array_filter(
				Scope_Store::granted_by( (array) $user_ids ),
				static function ( $row ) use ( $user_ids ) {
					// A deleted user's own passwords go with them; only list other users' passwords.
					return ! in_array( $row['user_id'], array_map( 'intval', (array) $user_ids ), true );
				}
			)
		);

		if ( ! $affected ) {
			return;
		}
		?>
		<div class="notice notice-warning inline">
			<p>
				<?php
				printf(
					/* translators: %s: number of application passwords. */
					esc_html( _n( '%s application password was created for another user by someone you are deleting. It will stop working, because a password can never do more than the person who granted it:', '%s application passwords were created for other users by someone you are deleting. They will stop working, because a password can never do more than the person who granted it:', count( $affected ), 'application-passwords-scoped' ) ),
					esc_html( number_format_i18n( count( $affected ) ) )
				);
				?>
			</p>
			<ul class="ul-disc">
				<?php foreach ( $affected as $row ) : ?>
					<?php
					$owner = get_userdata( $row['user_id'] );
					$item  = \WP_Application_Passwords::get_user_application_password( $row['user_id'], $row['uuid'] );
					if ( ! $owner || ! $item ) {
						continue;
					}
					?>
					<li>
						<?php
						printf(
							/* translators: 1: application password name, 2: owner's display name. */
							esc_html__( '"%1$s" for %2$s', 'application-passwords-scoped' ),
							esc_html( $item['name'] ),
							'<a href="' . esc_url( get_edit_user_link( $owner->ID ) . '#application-passwords-section' ) . '">' . esc_html( $owner->display_name ) . '</a>'
						);
						?>
					</li>
				<?php endforeach; ?>
			</ul>
			<p><?php esc_html_e( 'To keep one working, revoke it and have the user, or another administrator, create a replacement before you delete this account.', 'application-passwords-scoped' ); ?></p>
		</div>
		<?php
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
		$user    = get_userdata( $user_id );
		$scope   = Scope_Store::get( $user_id, $item['uuid'] );

		echo '<span class="app-password-scope-summary">' . esc_html( $scope->summary() ) . '</span>';

		if ( ! $user || ! current_user_can( 'edit_app_password', $user_id, $item['uuid'] ) ) {
			return;
		}
		?>
		<div class="app-password-scope-editor" data-user-id="<?php echo (int) $user_id; ?>" data-uuid="<?php echo esc_attr( $item['uuid'] ); ?>" data-name="<?php echo esc_attr( $item['name'] ); ?>">
			<button type="button" class="button-link app-password-scope-edit-toggle" aria-expanded="false">
				<?php esc_html_e( 'Edit access', 'application-passwords-scoped' ); ?>
			</button>
			<div class="app-password-scope-edit-panel" hidden>
				<?php
				// These inputs sit inside the profile form but are saved over REST. Strip their
				// names so the profile form neither submits them nor counts them as unsaved
				// changes (core compares a serialized snapshot); admin.js reads `data-name`.
				ob_start();
				self::render_fields(
					$scope,
					$user,
					array(
						'open'  => true,
						'field' => self::FIELD . '_edit[' . $item['uuid'] . ']',
						'class' => 'app-password-scope-edit',
					)
				);
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in render_fields(); only attribute names change.
				echo preg_replace( '/<(input|select)([^>]*?)\sname="/', '<$1$2 data-name="', ob_get_clean() );
				?>
				<p>
					<button type="button" class="button button-primary app-password-scope-edit-save"><?php esc_html_e( 'Save access', 'application-passwords-scoped' ); ?></button>
					<button type="button" class="button app-password-scope-edit-cancel"><?php esc_html_e( 'Cancel', 'application-passwords-scoped' ); ?></button>
					<span class="app-password-scope-edit-status" role="status"></span>
				</p>
			</div>
		</div>
		<?php
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
