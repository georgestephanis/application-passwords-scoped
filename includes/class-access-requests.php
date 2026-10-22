<?php
/**
 * Access requests: a scoped password asking its owner for a broader scope (issue #8).
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

use WP_Error;
use WP_REST_Request;
use WP_REST_Server;

/**
 * An app approved with a narrow scope can later ask for more, without the owner reissuing the
 * password and without the app ever widening its own scope.
 *
 * 1. The app, authenticated with its scoped password, calls
 *    `POST /application-passwords-scoped/v1/access-requests` with the `scope` it wants and a
 *    `reason`. This is the only write a scoped password can always make, alongside introspect.
 * 2. The owner sees a notice in wp-admin and on their profile, with the current and requested
 *    access side by side, and approves or denies it.
 * 3. Approving replaces the password's scope with the requested one. Because it's the owner (or
 *    another user able to edit the password) saving it, every normal rule still applies: it can't
 *    exceed the owner, or the granter if there is one.
 *
 * The app can poll `GET …/access-requests/<uuid>` for the outcome, or re-check introspect.
 *
 * One pending request per password; a new request replaces the old one.
 */
class Access_Requests {

	const NAMESPACE  = 'application-passwords-scoped/v1';
	const META_KEY   = '_application_password_scope_requests';
	const NONCE      = 'app_password_scope_request';
	const MAX_REASON = 500;

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_action( 'admin_post_app_password_scope_request', array( __CLASS__, 'handle_decision' ) );
		add_action( 'wp_delete_application_password', array( __CLASS__, 'cleanup' ), 10, 2 );
	}

	/**
	 * Register REST routes.
	 */
	public static function register_routes() {
		register_rest_route(
			self::NAMESPACE,
			'/access-requests',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'create' ),
				'permission_callback' => array( __CLASS__, 'can_request' ),
				'args'                => array(
					'scope'  => REST::schema(),
					'reason' => array(
						'description' => __( 'Shown to the user: why the app needs more access.', 'application-passwords-scoped' ),
						'type'        => 'string',
						'maxLength'   => self::MAX_REASON,
						'default'     => '',
					),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/access-requests/(?P<uuid>[\w-]+)',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'status' ),
				'permission_callback' => array( __CLASS__, 'can_request' ),
			)
		);
	}

	/**
	 * Only a request authenticated by an Application Password can ask, and only for itself.
	 *
	 * @return true|WP_Error
	 */
	public static function can_request() {
		if ( ! rest_get_authenticated_app_password() ) {
			return new WP_Error(
				'rest_forbidden',
				__( 'Access requests must be made with the Application Password that needs the access.', 'application-passwords-scoped' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		return true;
	}

	/**
	 * Record a request.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array|WP_Error
	 */
	public static function create( WP_REST_Request $request ) {
		$user_id = get_current_user_id();
		$uuid    = rest_get_authenticated_app_password();
		$current = Scope_Store::get( $user_id, $uuid );
		$wanted  = Scope::from_array( $request['scope'] );

		// The granter can't be requested away; approval keeps it.
		$wanted->granted_by = $current->granted_by;

		if ( $wanted->to_array() === $current->to_array() ) {
			return new WP_Error( 'application_password_scope_unchanged', __( 'The requested access is the same as the current access.', 'application-passwords-scoped' ), array( 'status' => 400 ) );
		}

		$all          = self::all( $user_id );
		$all[ $uuid ] = array(
			'scope'     => $wanted->to_array(),
			'reason'    => sanitize_textarea_field( $request['reason'] ),
			'requested' => time(),
		);
		update_user_meta( $user_id, self::META_KEY, $all );

		/**
		 * Fires when a scoped Application Password asks for more access.
		 *
		 * Hook this to notify the owner another way (email, Slack…).
		 *
		 * @param int    $user_id Owner.
		 * @param string $uuid    Application Password UUID.
		 * @param Scope  $wanted  Requested scope.
		 * @param Scope  $current Current scope.
		 * @param string $reason  App's reason.
		 */
		do_action( 'application_password_scope_access_requested', $user_id, $uuid, $wanted, $current, $all[ $uuid ]['reason'] );

		return self::status_for( $user_id, $uuid );
	}

	/**
	 * Status of the authenticated password's request.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return array|WP_Error
	 */
	public static function status( WP_REST_Request $request ) {
		if ( rest_get_authenticated_app_password() !== $request['uuid'] ) {
			return new WP_Error( 'rest_forbidden', __( 'A password can only check its own access request.', 'application-passwords-scoped' ), array( 'status' => 403 ) );
		}

		return self::status_for( get_current_user_id(), $request['uuid'] );
	}

	/**
	 * Response body for a password's request.
	 *
	 * @param int    $user_id Owner.
	 * @param string $uuid    Application Password UUID.
	 * @return array
	 */
	private static function status_for( $user_id, $uuid ) {
		$pending = self::all( $user_id )[ $uuid ] ?? null;
		$scope   = Scope_Store::get( $user_id, $uuid );

		return array(
			'uuid'      => $uuid,
			'status'    => $pending ? 'pending' : 'none',
			'requested' => $pending ? $pending['scope'] : null,
			'scope'     => $scope->to_array() + array( 'summary' => $scope->summary() ),
		);
	}

	/**
	 * Admin notice listing pending requests for passwords the viewer can edit.
	 */
	public static function notice() {
		$user_ids = array( get_current_user_id() );

		// On someone else's profile, show theirs too.
		$screen = get_current_screen();
		if ( $screen && 'user-edit' === $screen->id && isset( $_GET['user_id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
			$user_ids[] = (int) $_GET['user_id']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}

		foreach ( array_unique( $user_ids ) as $user_id ) {
			foreach ( self::all( $user_id ) as $uuid => $pending ) {
				$item = \WP_Application_Passwords::get_user_application_password( $user_id, $uuid );

				if ( ! $item || ! current_user_can( 'edit_app_password', $user_id, $uuid ) ) {
					continue;
				}

				self::render_request( $user_id, $item, $pending );
			}
		}
	}

	/**
	 * One request's notice.
	 *
	 * @param int   $user_id Owner.
	 * @param array $item    Application Password item.
	 * @param array $pending Stored request.
	 */
	private static function render_request( $user_id, array $item, array $pending ) {
		$current = Scope_Store::get( $user_id, $item['uuid'] );
		$wanted  = Scope::from_array( $pending['scope'] );
		$owner   = get_userdata( $user_id );
		$action  = admin_url( 'admin-post.php' );
		?>
		<div class="notice notice-info app-password-scope-request">
			<p>
				<strong>
					<?php
					if ( get_current_user_id() === $user_id ) {
						/* translators: %s: application password name. */
						printf( esc_html__( '"%s" is asking for more access.', 'application-passwords-scoped' ), esc_html( $item['name'] ) );
					} else {
						/* translators: 1: application password name, 2: owner's display name. */
						printf( esc_html__( '"%1$s" (%2$s) is asking for more access.', 'application-passwords-scoped' ), esc_html( $item['name'] ), esc_html( $owner->display_name ) );
					}
					?>
				</strong>
			</p>
			<?php if ( '' !== $pending['reason'] ) : ?>
				<blockquote><?php echo esc_html( $pending['reason'] ); ?></blockquote>
			<?php endif; ?>
			<table class="app-password-scope-compare">
				<tr><th scope="row"><?php esc_html_e( 'Now', 'application-passwords-scoped' ); ?></th><td><?php echo esc_html( $current->summary() ); ?></td></tr>
				<tr><th scope="row"><?php esc_html_e( 'Requested', 'application-passwords-scoped' ); ?></th><td><?php echo esc_html( $wanted->summary() ); ?></td></tr>
			</table>
			<form method="post" action="<?php echo esc_url( $action ); ?>">
				<input type="hidden" name="action" value="app_password_scope_request" />
				<input type="hidden" name="user_id" value="<?php echo (int) $user_id; ?>" />
				<input type="hidden" name="uuid" value="<?php echo esc_attr( $item['uuid'] ); ?>" />
				<?php wp_nonce_field( self::NONCE . '_' . $item['uuid'] ); ?>
				<p>
					<button type="submit" name="decision" value="approve" class="button button-primary"><?php esc_html_e( 'Approve', 'application-passwords-scoped' ); ?></button>
					<button type="submit" name="decision" value="deny" class="button"><?php esc_html_e( 'Deny', 'application-passwords-scoped' ); ?></button>
				</p>
			</form>
		</div>
		<?php
	}

	/**
	 * Approve or deny.
	 */
	public static function handle_decision() {
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
		$uuid    = isset( $_POST['uuid'] ) ? sanitize_key( wp_unslash( $_POST['uuid'] ) ) : '';

		check_admin_referer( self::NONCE . '_' . $uuid );

		if ( ! current_user_can( 'edit_app_password', $user_id, $uuid ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to change this application password.', 'application-passwords-scoped' ), 403 );
		}

		$decision = isset( $_POST['decision'] ) && 'approve' === $_POST['decision'] ? 'approve' : 'deny';
		self::decide( $user_id, $uuid, $decision );

		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url( 'profile.php' ) );
		exit;
	}

	/**
	 * Apply a decision as the current user. Public for WP-CLI and tests.
	 *
	 * @param int    $user_id  Owner.
	 * @param string $uuid     Application Password UUID.
	 * @param string $decision 'approve' or 'deny'.
	 * @return Scope|null New scope if approved.
	 */
	public static function decide( $user_id, $uuid, $decision ) {
		$all     = self::all( $user_id );
		$pending = $all[ $uuid ] ?? null;

		if ( ! $pending ) {
			return null;
		}

		unset( $all[ $uuid ] );
		self::save( $user_id, $all );

		$scope = null;
		if ( 'approve' === $decision ) {
			$scope = Scope_Store::save_from_request( $user_id, $uuid, $pending['scope'] );
		}

		/**
		 * Fires after an access request is approved or denied.
		 *
		 * @param string     $decision 'approve' or 'deny'.
		 * @param int        $user_id  Owner.
		 * @param string     $uuid     Application Password UUID.
		 * @param Scope|null $scope    New scope, if approved.
		 */
		do_action( 'application_password_scope_access_decided', $decision, (int) $user_id, $uuid, $scope );

		return $scope;
	}

	/**
	 * Drop a request when its password is deleted.
	 *
	 * @param int   $user_id User ID.
	 * @param array $item    Deleted item.
	 */
	public static function cleanup( $user_id, $item ) {
		$all = self::all( $user_id );

		if ( isset( $all[ $item['uuid'] ] ) ) {
			unset( $all[ $item['uuid'] ] );
			self::save( $user_id, $all );
		}
	}

	/**
	 * Pending requests for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array<string, array>
	 */
	private static function all( $user_id ) {
		$all = get_user_meta( $user_id, self::META_KEY, true );

		return is_array( $all ) ? $all : array();
	}

	/**
	 * Write pending requests, deleting the meta row when empty.
	 *
	 * @param int   $user_id User ID.
	 * @param array $all     Requests.
	 */
	private static function save( $user_id, array $all ) {
		if ( $all ) {
			update_user_meta( $user_id, self::META_KEY, $all );
		} else {
			delete_user_meta( $user_id, self::META_KEY );
		}
	}
}
