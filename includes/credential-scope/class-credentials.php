<?php
/**
 * The seam between authentication methods and the shared ceiling.
 *
 * @package Credential_Scope
 */

namespace Credential_Scope;

/**
 * Registry of credential types, and the credential the current request authenticated with.
 *
 * An authentication method plugs in with two calls:
 *
 *     Credentials::register_type( 'my_tokens', array( … ) ); // Once, at load.
 *     Credentials::set_current( new Credential( … ) );       // When it resolves the user.
 *
 * The Ceiling enforces from there. A method that resolves a user without calling set_current()
 * gets no ceiling at all, so it fails open; this layer can't detect that on its own.
 */
class Credentials {

	/**
	 * Registered types, keyed by name.
	 *
	 * @var array<string, array>
	 */
	private static $types = array();

	/**
	 * Credential in effect for this request, if restricted.
	 *
	 * @var Credential|null
	 */
	private static $current = null;

	/**
	 * Cache for escalation_caps(), keyed by the filter's callbacks.
	 *
	 * @var array{key: string, caps: string[]}|null
	 */
	private static $escalation_cache = null;

	/**
	 * Register a credential type.
	 *
	 * @param string $type Type name.
	 * @param array  $args {
	 *     Type handlers.
	 *
	 *     @type string[] $escalation_caps Meta capabilities that create, edit or delete credentials
	 *                                     of this type. A restricted credential of ANY type can
	 *                                     never use them, or it could mint an unrestricted one.
	 *     @type callable $granted_by      fn( int[] $granter_ids ): array of
	 *                                     array{ user_id: int, id: string, granted_by: int },
	 *                                     every credential those users issued for someone else.
	 *     @type callable $revoke          fn( int $user_id, string $id ): void.
	 * }
	 */
	public static function register_type( $type, array $args ) {
		self::$types[ $type ] = wp_parse_args(
			$args,
			array(
				'escalation_caps' => array(),
				'granted_by'      => null,
				'revoke'          => null,
			)
		);

		self::$escalation_cache = null;
	}

	/**
	 * Record the credential the current request authenticated with. Call this once the user is
	 * resolved, after rejecting expired credentials (see validate()).
	 *
	 * @param Credential $credential Credential.
	 */
	public static function set_current( Credential $credential ) {
		if ( ! isset( self::$types[ $credential->type ] ) ) {
			_doing_it_wrong( __METHOD__, esc_html( sprintf( 'Credential type "%s" is not registered.', $credential->type ) ), '0.1.0' );
		}

		self::$current = $credential->is_restricted() ? $credential : null;

		/**
		 * Fires when a request authenticates with a credential, restricted or not.
		 *
		 * @param Credential $credential Credential.
		 */
		do_action( 'credential_scope_authenticated', $credential );
	}

	/**
	 * The restricted credential in effect for this request, if any.
	 *
	 * @return Credential|null
	 */
	public static function current() {
		return self::$current;
	}

	/**
	 * Clear the current credential and cached state. For tests.
	 */
	public static function reset() {
		self::$current          = null;
		self::$escalation_cache = null;
	}

	/**
	 * Reasons a credential can't be honored on this request. Each authentication method should
	 * call this at its own rejection point and fail authentication on any error. The Ceiling also
	 * denies everything to a credential that fails it, so skipping the call fails closed.
	 *
	 * @param Credential $credential Credential.
	 * @return \WP_Error Error object; empty if the credential may be used.
	 */
	public static function validate( Credential $credential ) {
		$error = new \WP_Error();

		if ( $credential->is_expired() ) {
			$error->add( 'credential_expired', __( 'These credentials have expired.', 'application-passwords-scoped' ) );
		}

		if ( $credential->scope && ! Request::can_enforce( $credential->scope ) ) {
			$error->add( 'credential_scope_rest_only', __( 'These credentials are restricted to the REST API.', 'application-passwords-scoped' ) );
		}

		return $error;
	}

	/**
	 * Every meta capability that manages credentials, across all registered types.
	 *
	 * @return string[]
	 */
	public static function escalation_caps() {
		// Called on every capability check for a restricted credential, so build the list once.
		// The cache is keyed on the filter's callbacks rather than kept for the whole request: a
		// filter added after the first check must still apply, or its caps would fail open.
		$key = self::escalation_filter_key();

		if ( null === self::$escalation_cache || $key !== self::$escalation_cache['key'] ) {
			self::$escalation_cache = array(
				'key'  => $key,
				'caps' => self::build_escalation_caps(),
			);
		}

		return self::$escalation_cache['caps'];
	}

	/**
	 * Identifies the callbacks currently on `credential_scope_escalation_caps`. Cheap compared
	 * with re-running them; changes whenever one is added or removed.
	 *
	 * @return string
	 */
	private static function escalation_filter_key() {
		$hook = $GLOBALS['wp_filter']['credential_scope_escalation_caps'] ?? null;

		if ( ! $hook instanceof \WP_Hook ) {
			return '';
		}

		$ids = array();

		foreach ( $hook->callbacks as $priority => $callbacks ) {
			$ids[] = $priority . ':' . implode( ',', array_keys( $callbacks ) );
		}

		return implode( '|', $ids );
	}

	/**
	 * Merge every type's escalation caps and apply the filter.
	 *
	 * @return string[]
	 */
	private static function build_escalation_caps() {
		$caps = array();

		foreach ( self::$types as $args ) {
			$caps = array_merge( $caps, (array) $args['escalation_caps'] );
		}

		/**
		 * Filters the capabilities a restricted credential can never use.
		 *
		 * Add the capabilities that guard any other credential your plugin issues, even if it
		 * doesn't register a type: personal access tokens, API keys, OAuth clients.
		 *
		 * @param string[] $caps Meta capabilities.
		 */
		return array_values( array_unique( (array) apply_filters( 'credential_scope_escalation_caps', $caps ) ) );
	}

	/**
	 * Credentials of every type that some users issued for someone else.
	 *
	 * @param int[] $granter_ids Granters.
	 * @return array<int, array{type: string, user_id: int, id: string, granted_by: int}>
	 */
	public static function granted_by( array $granter_ids ) {
		$rows = array();

		foreach ( self::$types as $type => $args ) {
			if ( ! is_callable( $args['granted_by'] ) ) {
				continue;
			}

			foreach ( (array) call_user_func( $args['granted_by'], $granter_ids ) as $row ) {
				$rows[] = array( 'type' => $type ) + $row;
			}
		}

		return $rows;
	}

	/**
	 * Revoke one credential through its type.
	 *
	 * @param string $type    Type.
	 * @param int    $user_id Owner.
	 * @param string $id      Identifier.
	 */
	public static function revoke( $type, $user_id, $id ) {
		if ( isset( self::$types[ $type ] ) && is_callable( self::$types[ $type ]['revoke'] ) ) {
			call_user_func( self::$types[ $type ]['revoke'], (int) $user_id, (string) $id );
		}
	}
}
