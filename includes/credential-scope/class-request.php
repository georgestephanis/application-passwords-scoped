<?php
/**
 * Classifies the current request: does it only read, and will the REST API serve it?
 *
 * @package Credential_Scope
 */

namespace Credential_Scope;

/**
 * Request classification shared by every credential type. Read-only is decided here and nowhere
 * else.
 */
class Request {

	/**
	 * Whether a request only reads.
	 *
	 * On REST the default is method-based: GET, HEAD and OPTIONS read, everything else writes. That
	 * is the effective method: core applies `?_method=` and `X-HTTP-Method-Override` to the request
	 * before dispatch, and routes on the result, so an override can't disguise a write.
	 *
	 * On XML-RPC the default is by method name: `get*` and `supported*` methods read (wp.getPosts,
	 * mt.supportedMethods…), everything else writes. `system.multicall` counts as a write, since
	 * one call can't vouch for the ones inside it.
	 *
	 * Anywhere else the default is "writes", because nothing here can tell. Plugins know better in both
	 * directions: a GraphQL endpoint can say a POSTed query only reads and a mutation doesn't; a
	 * REST route can say a POST search only reads, or that a GET has side effects.
	 *
	 * @param \WP_REST_Request|null $request REST request, or null off REST (inspect the globals).
	 * @return bool
	 */
	public static function is_read_only( $request ) {
		$xmlrpc_method = self::xmlrpc_method();

		if ( $request instanceof \WP_REST_Request ) {
			$default = in_array( $request->get_method(), array( 'GET', 'HEAD', 'OPTIONS' ), true );
		} elseif ( null !== $xmlrpc_method ) {
			$last    = substr( (string) strrchr( '.' . $xmlrpc_method, '.' ), 1 );
			$default = 0 === strpos( $last, 'get' ) || 0 === strpos( $last, 'supported' );
		} else {
			$default = false;
		}

		/**
		 * Filters whether a request only reads, for read-only credentials of any type.
		 *
		 * Return true only if the request can't change anything; read-only credentials trust it.
		 *
		 * @param bool                  $is_read_only  Default decision.
		 * @param \WP_REST_Request|null $request       REST request, or null for a non-REST endpoint.
		 * @param string|null           $xmlrpc_method XML-RPC method being called, if any.
		 */
		return (bool) apply_filters( 'credential_scope_request_is_read_only', $default, $request, $xmlrpc_method );
	}

	/**
	 * Whether the current request will be served by the REST API, where the request gates run.
	 *
	 * Credentials can authenticate on REST, on XML-RPC, and on any endpoint a plugin approves.
	 * Plugins commonly approve REST URLs before core has defined REST_REQUEST, so the constant
	 * alone would reject real REST requests. The URL is checked as well: if it routes to the REST
	 * API, the gates will still see it.
	 *
	 * @return bool
	 */
	public static function is_rest_bound() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return false;
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput -- Routing check only; nothing is stored or output.
		if ( isset( $_GET['rest_route'] ) ) {
			return true;
		}

		$path   = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) : '';
		$prefix = trailingslashit( wp_parse_url( get_rest_url(), PHP_URL_PATH ) );
		// phpcs:enable

		return '' !== $path && 0 === strpos( trailingslashit( $path ), $prefix );
	}

	/**
	 * Whether a restriction can be honored on the current request.
	 *
	 * Request-level rules (read-only, abilities) are only enforced on the REST API, except that
	 * read-only also holds wherever the request is known to only read (XML-RPC `get*`, or a plugin
	 * declaring it). Capability rules work everywhere.
	 *
	 * @param Restriction $scope Restriction.
	 * @return bool
	 */
	public static function can_enforce( Restriction $scope ) {
		if ( self::is_rest_bound() ) {
			return true;
		}

		return ! $scope->requires_rest() && ( ! $scope->restricts_to_reads() || self::is_read_only( null ) );
	}

	/**
	 * The XML-RPC method being called, or null outside XML-RPC. xmlrpc.php assigns the server to
	 * the global before serving, and IXR parses the message before calling the method that
	 * authenticates, so this is available whenever a credential is checked.
	 *
	 * @return string|null
	 */
	public static function xmlrpc_method() {
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return null;
		}

		$server = $GLOBALS['wp_xmlrpc_server'] ?? null;

		// No parsed message means we can't tell; an empty name is never read-only.
		return isset( $server->message->methodName ) ? (string) $server->message->methodName : '';
	}
}
