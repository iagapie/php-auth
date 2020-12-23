<?php

declare(strict_types=1);

namespace IA\Auth\Passport\Credentials;

use LogicException;

class PasswordCredentials implements CredentialsInterface
{
    /**
     * @var bool
     */
    protected bool $resolved = false;

    /**
     * @var string|null
     */
    protected ?string $password;

    /**
     * PasswordCredentials constructor.
     * @param string $password
     */
    public function __construct(string $password)
    {
        $this->password = $password;
    }

    /**
     * @return string
     */
    public function getPassword(): string
    {
        if (null === $this->password) {
            throw new LogicException('The credentials are erased.');
        }

        return $this->password;
    }

    public function markResolved(): void
    {
        $this->resolved = true;
        $this->password = null;
    }

    /**
     * {@inheritDoc}
     */
    public function isResolved(): bool
    {
        return $this->resolved;
    }
}