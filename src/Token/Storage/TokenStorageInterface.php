<?php

declare(strict_types=1);

namespace IA\Auth\Token\Storage;

use IA\Auth\Token\TokenInterface;

interface TokenStorageInterface
{
    /**
     * Returns the current security token.
     *
     * @return TokenInterface|null A TokenInterface instance or null if no authentication information is available
     */
    public function getToken(): ?TokenInterface;

    /**
     * Sets the authentication token.
     *
     * @param TokenInterface|null $token A TokenInterface token, or null if no further authentication information should be stored
     */
    public function setToken(?TokenInterface $token = null): void;
}