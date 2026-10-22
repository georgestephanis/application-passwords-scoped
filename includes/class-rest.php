<?php
/**
 * REST API surface: a `scope` field on the core application-passwords endpoints.
 *
 * @package Application_Passwords_Scoped
 */

namespace Application_Passwords_Scoped;

/**
 * Adds `scope` to `/wp/v2/users/<id>/application-passwords[/<uuid>|/introspect]`.
 *
 * - POST (create) and PUT (update) accept it, so the profile screen, the authorize-app flow,
 *   and any other client can set restrictions using the existing endpoints.
 * - GET returns it, including `introspect`, so an app can discover what it was actually granted.
 */
class REST {

	/**
	 * Register hooks.
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_field' ) );
	}

	/**
	 * Register the field.
	 */
	public static function register_field() {
		register_rest_field(
			'application-password',
			'scope',
			array(
				'get_callback'    => array( __CLASS__, 'get_scope' ),
				'update_callback' => array( __CLASS__, 'update_scope' ),
				'schema'          => self::schema(),
			)
		);
	}

	/**
	 * Field schema.
	 *
	 * @return array
	 */
	public static function schema() {
		return array(
			'description' => __( 'Restrictions on what this application password may do. Omit or send an empty object for full access.', 'application-passwords-scoped' ),
			'type'        => 'object',
			'context'     => array( 'view', 'edit', 'embed' ),
			'properties'  => array(
				'role'           => array(
					'description' => __( 'Role slug used as a capability ceiling.', 'application-passwords-scoped' ),
					'type'        => 'string',
					'enum'        => array_merge( array( '' ), array_keys( wp_roles()->get_names() ) ),
				),
				'deny'           => array(
					'description' => __( 'Capability groups withheld from this password.', 'application-passwords-scoped' ),
					'type'        => 'array',
					'items'       => array(
						'type' => 'string',
						'enum' => array_keys( Capability_Groups::all() ),
					),
				),
				'read_only'      => array(
					'description' => __( 'Only allow non-mutating requests.', 'application-passwords-scoped' ),
					'type'        => 'boolean',
				),
				'abilities'      => array(
					'description' => __( 'Ability names (wildcards allowed) this password may execute. null for no restriction.', 'application-passwords-scoped' ),
					'type'        => array( 'array', 'null' ),
					'items'       => array( 'type' => 'string' ),
				),
				'abilities_only' => array(
					'description' => __( 'Restrict REST access to the Abilities API.', 'application-passwords-scoped' ),
					'type'        => 'boolean',
				),
				'expires'        => array(
					'description' => __( 'Unix timestamp after which the password stops working. 0 for never.', 'application-passwords-scoped' ),
					'type'        => 'integer',
					'minimum'     => 0,
				),
				'expires_in'     => array(
					'description' => __( 'Write-only convenience: seconds from now until the password expires. Takes precedence over expires.', 'application-passwords-scoped' ),
					'type'        => 'integer',
					'minimum'     => 0,
				),
				'summary'        => array(
					'description' => __( 'Human readable summary.', 'application-passwords-scoped' ),
					'type'        => 'string',
					'readonly'    => true,
				),
			),
		);
	}

	/**
	 * Read the scope for a response.
	 *
	 * @param array            $item    Prepared response data (has `uuid`).
	 * @param string           $field   Field name.
	 * @param \WP_REST_Request $request Request.
	 * @return array
	 */
	public static function get_scope( $item, $field, $request ) {
		$scope = Scope_Store::get( self::user_id( $request ), $item['uuid'] );

		return $scope->to_array() + array( 'summary' => $scope->summary() );
	}

	/**
	 * Save the scope from a create/update request.
	 *
	 * @param mixed            $value   Submitted value.
	 * @param array            $item    Application Password item.
	 * @param string           $field   Field name.
	 * @param \WP_REST_Request $request Request.
	 * @return true
	 */
	public static function update_scope( $value, $item, $field, $request ) {
		Scope_Store::set( self::user_id( $request ), $item['uuid'], Scope::from_array( $value ) );

		return true;
	}

	/**
	 * Resolve the `user_id` URL param (which may be `me`).
	 *
	 * @param \WP_REST_Request $request Request.
	 * @return int
	 */
	private static function user_id( $request ) {
		$user_id = $request['user_id'];

		return 'me' === $user_id ? get_current_user_id() : (int) $user_id;
	}
}
