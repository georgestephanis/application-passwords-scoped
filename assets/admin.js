/* global jQuery */

/**
 * Scope forms on the profile and Authorize Application screens.
 *
 * - Adds `scope` to the create-password requests core's own scripts send
 *   (wp-admin/js/application-passwords.js and wp-admin/js/auth-app.js), via their wp.hooks filters.
 * - Saves the inline "Edit access" forms in the passwords list table, with a REST PUT.
 *
 * Several forms can be on one page (create, plus one editor per password), so everything works
 * from a form's root element rather than global selectors.
 *
 * @param {jQuery} $        jQuery.
 * @param {Object} hooks    wp.hooks.
 * @param {Object} apiFetch wp.apiFetch.
 * @param {Object} i18n     wp.i18n.
 */
( function ( $, hooks, apiFetch, i18n ) {
	const { __ } = i18n;

	/**
	 * Select a form input by the end of its name. Inline editors keep the name in `data-name`
	 * (see Admin::column()), so match either attribute.
	 *
	 * @param {jQuery} $root  Form root.
	 * @param {string} suffix Name suffix, e.g. `[read_only]`.
	 * @param {string} extra  Extra selector, e.g. `:checked`.
	 * @return {jQuery} Matching inputs.
	 */
	function field( $root, suffix, extra = '' ) {
		return $root.find(
			'[name$="' +
				suffix +
				'"]' +
				extra +
				', [data-name$="' +
				suffix +
				'"]' +
				extra
		);
	}

	const CREATE_FORM = '.app-password-scope:not(.app-password-scope-edit)';

	/**
	 * Values of the checked inputs whose name ends with a suffix.
	 *
	 * @param {jQuery} $root  Form root.
	 * @param {string} suffix Input name suffix.
	 * @return {string[]} Values.
	 */
	function checkedValues( $root, suffix ) {
		return field( $root, suffix, ':checked' )
			.map( function () {
				return this.value;
			} )
			.get();
	}

	/**
	 * Read a scope form into the shape the REST `scope` field expects.
	 *
	 * Disabled inputs are read too: on the authorize screen, restrictions the app asked for are
	 * shown checked and disabled, and must still be sent.
	 *
	 * @param {jQuery} $root Form root.
	 * @return {Object|null} Scope, or null when there's no form.
	 */
	function readScope( $root ) {
		if ( ! $root.length ) {
			return null;
		}

		const $expires = field( $root, '[expires_in]' );
		const scope = {
			read_only: field( $root, '[read_only]' ).is( ':checked' ),
			abilities_only: field( $root, '[abilities_only]' ).is( ':checked' ),
			block_xmlrpc: field( $root, '[block_xmlrpc]' ).is( ':checked' ),
			deny: checkedValues( $root, '[deny][]' ),
		};

		// "Unchanged" on the edit form keeps the existing expiry instead of restarting the clock.
		if ( 'keep' === $expires.val() ) {
			scope.expires = parseInt( $expires.data( 'expires' ), 10 ) || 0;
		} else {
			scope.expires_in = parseInt( $expires.val(), 10 ) || 0;
		}

		scope.roles = readRoles( $root );
		if ( null === scope.roles ) {
			delete scope.roles;
		} else if ( ! scope.roles.length ) {
			scope.roles = [ '' ];
		}

		// Leave `abilities` out entirely when unrestricted: requests are form-encoded, which would
		// turn null into '' and read as "no abilities allowed". An empty list is sent as [''].
		if (
			$root
				.find( '.app-password-scope-restrict-abilities' )
				.is( ':checked' )
		) {
			scope.abilities = checkedValues( $root, '[abilities][]' );

			if ( ! scope.abilities.length ) {
				scope.abilities = [ '' ];
			}
		}

		return scope;
	}

	/**
	 * Mirrors Admin::normalize_form(): the core-role radios plus the additional-role checkboxes
	 * become one `roles` list, or null when nothing is limited.
	 *
	 * @param {jQuery} $root Form root.
	 * @return {string[]|null} Role slugs, or null for no role restriction.
	 */
	function readRoles( $root ) {
		const base = field( $root, '[base_role]', ':checked' ).val() || '';
		const $extras = field( $root, '[keep_roles][]' );
		const kept = checkedValues( $root, '[keep_roles][]' );

		if ( '' === base && kept.length === $extras.length ) {
			return null;
		}

		let baseRoles;
		if ( '' === base ) {
			baseRoles = $root.data( 'ownRoles' ) || [];
		} else {
			baseRoles = '__none__' === base ? [] : [ base ];
		}

		return baseRoles.concat( kept );
	}

	/**
	 * Filter callback: add `scope` to a create-password request.
	 *
	 * @param {Object} request REST request data.
	 * @return {Object} Request data, with `scope` when the form is present.
	 */
	function addScope( request ) {
		const scope = readScope( $( CREATE_FORM ).first() );

		if ( scope ) {
			request.scope = scope;
		}

		return request;
	}

	/**
	 * Dim a form's ability list unless "Only allow these abilities" is checked.
	 *
	 * @param {jQuery} $root Form root.
	 */
	function syncAbilities( $root ) {
		$root
			.find( '.app-password-scope-abilities' )
			.toggleClass(
				'is-disabled',
				! $root
					.find( '.app-password-scope-restrict-abilities' )
					.is( ':checked' )
			);
	}

	/**
	 * Save an inline edit form.
	 *
	 * @param {jQuery} $editor The row's `.app-password-scope-editor`.
	 */
	function saveEdit( $editor ) {
		const $status = $editor.find( '.app-password-scope-edit-status' );
		const $save = $editor.find( '.app-password-scope-edit-save' );

		$save.prop( 'disabled', true );
		$status.text( __( 'Saving…', 'application-passwords-scoped' ) );

		apiFetch( {
			path:
				'/wp/v2/users/' +
				$editor.data( 'userId' ) +
				'/application-passwords/' +
				$editor.data( 'uuid' ),
			method: 'PUT',
			// Core requires `name` on update even when it isn't changing.
			data: {
				name: String( $editor.data( 'name' ) ),
				scope: readScope( $editor.find( '.app-password-scope' ) ),
			},
		} )
			.then( function ( response ) {
				$editor
					.closest( 'td' )
					.find( '.app-password-scope-summary' )
					.text( response.scope ? response.scope.summary : '' );
				$status.text( __( 'Saved.', 'application-passwords-scoped' ) );
				toggleEdit( $editor, false );
			} )
			.catch( function ( error ) {
				$status.text(
					error && error.message
						? error.message
						: __(
								'Could not save.',
								'application-passwords-scoped'
							)
				);
			} )
			.finally( function () {
				$save.prop( 'disabled', false );
			} );
	}

	/**
	 * Show or hide a row's edit panel.
	 *
	 * @param {jQuery}  $editor The row's `.app-password-scope-editor`.
	 * @param {boolean} open    Whether to open it.
	 */
	function toggleEdit( $editor, open ) {
		$editor
			.find( '.app-password-scope-edit-panel' )
			.prop( 'hidden', ! open );
		$editor
			.find( '.app-password-scope-edit-toggle' )
			.attr( 'aria-expanded', open ? 'true' : 'false' );
	}

	hooks.addFilter(
		'wp_application_passwords_new_password_request',
		'application-passwords-scoped',
		addScope
	);
	hooks.addFilter(
		'wp_application_passwords_approve_app_request',
		'application-passwords-scoped',
		addScope
	);

	// Reset the create form after a password is created on the profile screen.
	hooks.addAction(
		'wp_application_passwords_created_password',
		'application-passwords-scoped',
		function () {
			const $root = $( CREATE_FORM );
			$root
				.find( 'input[type=checkbox]' )
				.not( '[name$="[keep_roles][]"]' )
				.prop( 'checked', false );
			$root.find( 'select' ).val( '0' );
			field( $root, '[base_role]', '[value=""]' ).prop( 'checked', true );
			field( $root, '[keep_roles][]' ).prop( 'checked', true );
			$root.prop( 'open', false );
			syncAbilities( $root );
		}
	);

	$( document )
		.on( 'change', '.app-password-scope-restrict-abilities', function () {
			syncAbilities( $( this ).closest( '.app-password-scope' ) );
		} )
		.on( 'click', '.app-password-scope-edit-toggle', function () {
			const $editor = $( this ).closest( '.app-password-scope-editor' );
			toggleEdit(
				$editor,
				$editor
					.find( '.app-password-scope-edit-panel' )
					.prop( 'hidden' )
			);
		} )
		.on( 'click', '.app-password-scope-edit-cancel', function () {
			toggleEdit(
				$( this ).closest( '.app-password-scope-editor' ),
				false
			);
		} )
		.on( 'click', '.app-password-scope-edit-save', function () {
			saveEdit( $( this ).closest( '.app-password-scope-editor' ) );
		} );

	$( function () {
		$( '.app-password-scope' ).each( function () {
			syncAbilities( $( this ) );
		} );
	} );
} )( jQuery, wp.hooks, wp.apiFetch, wp.i18n );
