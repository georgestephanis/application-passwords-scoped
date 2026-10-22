/**
 * Adds the scope fields to the REST request core's Application Password scripts send.
 */
( function( $, hooks ) {
	function readScope() {
		var $root = $( '.app-password-scope' ).first(),
			scope;

		if ( ! $root.length ) {
			return null;
		}

		scope = {
			role: $root.find( 'select[name$="[role]"]' ).val() || '',
			expires_in: parseInt( $root.find( 'select[name$="[expires_in]"]' ).val(), 10 ) || 0,
			read_only: $root.find( 'input[name$="[read_only]"]' ).is( ':checked' ),
			abilities_only: $root.find( 'input[name$="[abilities_only]"]' ).is( ':checked' ),
			deny: $root.find( 'input[name$="[deny][]"]:checked' ).map( function() {
				return this.value;
			} ).get()
		};

		// Leave `abilities` out entirely when unrestricted: requests are form-encoded, which would
		// turn null into '' and read as "no abilities allowed". An empty list is sent as [''].
		if ( $root.find( '.app-password-scope-restrict-abilities' ).is( ':checked' ) ) {
			scope.abilities = $root.find( 'input[name$="[abilities][]"]:checked' ).map( function() {
				return this.value;
			} ).get();

			if ( ! scope.abilities.length ) {
				scope.abilities = [ '' ];
			}
		}

		return scope;
	}

	function addScope( request ) {
		var scope = readScope();

		if ( scope ) {
			request.scope = scope;
		}

		return request;
	}

	function syncAbilities() {
		$( '.app-password-scope-abilities' ).toggleClass(
			'is-disabled',
			! $( '.app-password-scope-restrict-abilities' ).is( ':checked' )
		);
	}

	hooks.addFilter( 'wp_application_passwords_new_password_request', 'application-passwords-scoped', addScope );
	hooks.addFilter( 'wp_application_passwords_approve_app_request', 'application-passwords-scoped', addScope );

	// Reset the form after a password is created on the profile screen.
	hooks.addAction( 'wp_application_passwords_created_password', 'application-passwords-scoped', function() {
		var $root = $( '.app-password-scope' );
		$root.find( 'input[type=checkbox]' ).prop( 'checked', false );
		$root.find( 'select' ).val( '' );
		$root.prop( 'open', false );
		syncAbilities();
	} );

	$( document ).on( 'change', '.app-password-scope-restrict-abilities', syncAbilities );
	$( syncAbilities );
}( jQuery, wp.hooks ) );
