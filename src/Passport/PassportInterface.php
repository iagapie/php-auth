<?php

declare(strict_types=1);

namespace IA\Auth\Passport;

use IA\Auth\Exception\BadCredentialsException;
use IA\Auth\Passport\Badge\BadgeInterface;

interface PassportInterface
{
    /**
     * Adds a new security badge.
     *
     * A passport can hold only one instance of the same security badge.
     * This method replaces the current badge if it is already set on this
     * passport.
     *
     * @param BadgeInterface $badge
     * @return $this
     */
    public function addBadge(BadgeInterface $badge): PassportInterface;

    /**
     * @param string $badgeFqcn
     * @return bool
     */
    public function hasBadge(string $badgeFqcn): bool;

    /**
     * @param string $badgeFqcn
     * @return BadgeInterface|null
     */
    public function getBadge(string $badgeFqcn): ?BadgeInterface;

    /**
     * Checks if all badges are marked as resolved.
     *
     * @throws BadCredentialsException when a badge is not marked as resolved
     */
    public function checkIfCompletelyResolved(): void;

    /**
     * @param string $name
     * @param mixed $value
     */
    public function setAttribute(string $name, mixed $value): void;

    /**
     * @param string $name
     * @param mixed $default
     * @return mixed
     */
    public function getAttribute(string $name, mixed $default = null): mixed;
}