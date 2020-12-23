<?php

declare(strict_types=1);

namespace IA\Auth\Event;

use IA\Auth\Token\TokenInterface;
use Symfony\Contracts\EventDispatcher\Event;

class AuthenticationSuccessEvent extends Event
{
    /**
     * AuthenticationEvent constructor.
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
}