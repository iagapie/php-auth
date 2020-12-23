<?php

declare(strict_types=1);

namespace IA\Auth;

/**
 * This is an extension of the authenticator interface that must
 * be used by interactive authenticators.
 *
 * Interactive login requires explicit user action (e.g. a login
 * form or HTTP basic authentication). Implementing this interface
 * will dispatcher the InteractiveLoginEvent upon successful login.
 *
 * @author Wouter de Jong <wouter@wouterj.nl>
 */
interface InteractiveAuthInterface extends AuthInterface
{
    /**
     * Should return true to make this authenticator perform
     * an interactive login.
     */
    public function isInteractive(): bool;
}