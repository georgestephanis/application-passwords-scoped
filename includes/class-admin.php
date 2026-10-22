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
	 * `authorize-application.php?app_name=Foo&scope[role]=author&scope[deny]=plugins,users&scope[expires_in]=86400`.
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
		$roles     = array_reverse( wp_roles()->get_names(), true );
		$abilities = function_exists( 'wp_get_abilities' ) ? wp_get_abilities() : array();

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
		<details class="app-password-scope" <?php echo $open || $scope->is_restricted() ? 'open' : ''; ?>>
			<summary><?php esc_html_e( 'Limit what this password can do', 'application-passwords-scoped' ); ?></summary>

			<p class="description">
				<?php esc_html_e( 'Restrictions only ever remove access. The password can never do more than your own account can.', 'application-passwords-scoped' ); ?>
			</p>

			<fieldset>
				<legend><?php esc_html_e( 'Access level', 'application-passwords-scoped' ); ?></legend>
				<label>
					<input type="checkbox" name="<?php echo esc_attr( $field ); ?>[read_only]" value="1" <?php checked( $scope->read_only ); ?> />
					<?php esc_html_e( 'Read-only — can view but not change anything', 'application-passwords-scoped' ); ?>
				</label>
				<label class="app-password-scope-role">
					<?php esc_html_e( 'Act with at most the permissions of:', 'application-passwords-scoped' ); ?>
					<select name="<?php echo esc_attr( $field ); ?>[role]">
						<option value=""><?php esc_html_e( '— My own role (no limit) —', 'application-passwords-scoped' ); ?></option>
						<?php foreach ( $roles as $slug => $name ) : ?>
							<option value="<?php echo esc_attr( $slug ); ?>" <?php selected( $scope->role, $slug ); ?>><?php echo esc_html( translate_user_role( $name ) ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
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
		Scope_Store::set( $user_id, $item['uuid'], Scope::from_array( self::normalize_form( wp_unslash( $_POST[ self::FIELD ] ) ) ) );
		// phpcs:enable
	}

	/**
	 * The form uses a `restrict_abilities` toggle to distinguish "no ability restriction" (null)
	 * from "no abilities allowed" (empty list).
	 *
	 * @param array $data Raw form data.
	 * @return array
	 */
	private static function normalize_form( $data ) {
		$data = (array) $data;

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
