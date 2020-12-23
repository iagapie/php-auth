<?php

declare(strict_types=1);

namespace IA\Auth\Event;

use IA\Auth\Token\TokenInterface;
use Psr\Http\Message\ServerRequestInterface;

class LogoutEvent extends AuthEvent
{
    /**
     * @param ServerRequestInterface $request
     * @param TokenInterface|null $authToken
     */
    public function __construct(ServerRequestInterface $request, protected ?TokenInterface $authToken = null)
    {
        parent::__construct($request);
    }

    /**
     * @return TokenInterface|null
     */
    public function getAuthToken(): ?TokenInterface
    {
        return $this->authToken;
    }
}