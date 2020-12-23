<?php

declare(strict_types=1);

namespace IA\Auth\Passport;

use IA\Auth\Exception\BadCredentialsException;
use IA\Auth\Passport\Badge\BadgeInterface;

use function sprintf;

trait PassportTrait
{
    /**
     * @var BadgeInterface[]
     */
    private array $badges = [];

    /**
     * @var array
     */
    private array $attributes = [];

    /**
     * @param BadgeInterface $badge
     * @return PassportInterface
     */
    public function addBadge(BadgeInterface $badge): PassportInterface
    {
        $this->badges[$badge::class] = $badge;

        return $this;
    }

    /**
     * @param string $badgeFqcn
     * @return bool
     */
    public function hasBadge(string $badgeFqcn): bool
    {
        return isset($this->badges[$badgeFqcn]);
    }

    /**
     * @param string $badgeFqcn
     * @return BadgeInterface|null
     */
    public function getBadge(string $badgeFqcn): ?BadgeInterface
    {
        return $this->badges[$badgeFqcn] ?? null;
    }

    public function checkIfCompletelyResolved(): void
    {
        foreach ($this->badges as $badge) {
            if (!$badge->isResolved()) {
                throw new BadCredentialsException(
                    sprintf(
                        'Authentication failed security badge "%s" is not resolved, did you forget to register the correct listeners?',
                        $badge::class
                    )
                );
            }
        }
    }

    /**
     * @param string $name
     * @param mixed $value
     */
    public function setAttribute(string $name, mixed $value): void
    {
        $this->attributes[$name] = $value;
    }

    /**
     * @param string $name
     * @param mixed $default
     *
     * @return mixed
     */
    public function getAttribute(string $name, mixed $default = null): mixed
    {
        return $this->attributes[$name] ?? $default;
    }
}