<?php

declare(strict_types=1);

namespace IA\Auth\Passport\Badge;

/**
 * Marks the authentication as being pre-authenticated.
 * This disables pre-authentication user checkers.
 *
 * @author Wouter de Jong <wouter@wouterj.nl>
 */
class PreAuthenticatedUserBadge implements BadgeInterface
{
    /**
     * {@inheritDoc}
     */
    public function isResolved(): bool
    {
        return true;
    }
}