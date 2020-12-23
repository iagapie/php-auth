<?php

declare(strict_types=1);

namespace IA\Auth\Event;

use IA\Auth\Token\TokenInterface;
use Symfony\Contracts\EventDispatcher\Event;

class AuthenticationTokenCreatedEvent extends Event
{
    /**
     * @param TokenInterface $authToken
     */
    public function __construct(private TokenInterface $authToken)
    {
    }

    /**
     * @return TokenInterface
     */
    public function getAuthToken(): TokenInterface
    {
        return $this->authToken;
    }

    /**
     * @param TokenInterface $authToken
     */
    public function setAuthToken(TokenInterface $authToken): void
    {
        $this->authToken = $authToken;
    }
}