<?php

declare(strict_types=1);

namespace IA\Auth\Passport\Credentials;

use IA\Auth\Exception\BadCredentialsException;
use IA\Auth\User\UserInterface;

class CustomCredentials implements CredentialsInterface
{
    /**
     * @var callable
     */
    protected $customCredentialsChecker;

    /**
     * @var mixed
     */
    protected mixed $credentials;

    /**
     * @var bool
     */
    protected bool $resolved = false;

    /**
     * @param callable $customCredentialsChecker the check function. If this function does not return `true`, a
     *                                           BadCredentialsException is thrown. You may also throw a more
     *                                           specific exception in the function.
     * @param mixed $credentials
     */
    public function __construct(callable $customCredentialsChecker, mixed $credentials)
    {
        $this->customCredentialsChecker = $customCredentialsChecker;
        $this->credentials = $credentials;
    }

    /**
     * @param UserInterface $user
     */
    public function executeCustomChecker(UserInterface $user): void
    {
        $checker = $this->customCredentialsChecker;

        if (true !== $checker($this->credentials, $user)) {
            throw new BadCredentialsException(
                'Credentials check failed as the callable passed to CustomCredentials did not return "true".'
            );
        }

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