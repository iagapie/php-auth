<?php

declare(strict_types=1);

namespace IA\Auth\Passport\Badge;

interface BadgeInterface
{
    /**
     * Checks if this badge is resolved by the security system.
     *
     * After authentication, all badges must return `true` in this method in order
     * for the authentication to succeed.
     *
     * @return bool
     */
    public function isResolved(): bool;
}