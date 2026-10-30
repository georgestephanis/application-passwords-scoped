<?php
/**
 * Credential Scope: a capability ceiling any authentication method can attach to.
 *
 * Nothing in this directory knows about Application Passwords. It is kept separate so it can be
 * lifted out on its own: into a standalone library, or as a core proposal. See README.md.
 *
 * @package Credential_Scope
 */

namespace Credential_Scope;

// Several plugins may bundle this layer; the first copy loaded wins, as with other shared libraries.
if ( class_exists( __NAMESPACE__ . '\Ceiling' ) ) {
	return;
}

require_once __DIR__ . '/interface-restriction.php';
require_once __DIR__ . '/class-credential.php';
require_once __DIR__ . '/class-request.php';
require_once __DIR__ . '/class-credentials.php';
require_once __DIR__ . '/class-ceiling.php';

Ceiling::init();
