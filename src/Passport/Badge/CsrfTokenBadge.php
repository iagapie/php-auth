<?php

declare(strict_types=1);

namespace IA\Auth\Passport\Badge;

class CsrfTokenBadge implements BadgeInterface
{
    /**
     * @var bool
     */
    protected bool $resolved = false;

    /**
     * CsrfTokenBadge constructor.
     * @param string $csrfTokenId An arbitrary string used to generate the value of the CSRF token.
     *                            Using a different string for each authenticator improves its security.
     * @param string|null $csrfToken The CSRF token presented in the request, if any
     */
    public function __construct(protected string $csrfTokenId, protected ?string $csrfToken)
    {
    }

    /**
     * @return string
     */
    public function getCsrfTokenId(): string
    {
        return $this->csrfTokenId;
    }

    /**
     * @return string|null
     */
    public function getCsrfToken(): ?string
    {
        return $this->csrfToken;
    }

    public function markResolved(): void
    {
        $this->resolved = true;
    }

    /**
     * {@inheritDoc}
     */
    public function isResolved(): bool
    {
        return $this->resolved;
    }
}