<?php

declare(strict_types=1);

namespace IA\Auth\Passport\Badge;

/**
 * Adds support for remember me to this authenticator.
 *
 * Remember me cookie will be set if *all* of the following are met:
 *  A) This badge is present in the Passport
 *  B) The remember_me key under your firewall is configured
 *  C) The "remember me" functionality is activated. This is usually
 *      done by having a _remember_me checkbox in your form, but
 *      can be configured by the "always_remember_me" and "remember_me_parameter"
 *      parameters under the "remember_me" firewall key
 *  D) The authentication process returns a success Response object
 *
 * @author Wouter de Jong <wouter@wouterj.nl>
 */
class RememberMeBadge implements BadgeInterface
{
    /**
     * {@inheritDoc}
     */
    public function isResolved(): bool
    {
        return true;
    }
}