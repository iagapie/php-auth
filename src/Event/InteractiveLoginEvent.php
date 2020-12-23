<?php

declare(strict_types=1);

namespace IA\Auth\Event;

use IA\Auth\Token\TokenInterface;
use Psr\Http\Message\ServerRequestInterface;

class InteractiveLoginEvent extends AuthEvent
{
    /**
     * @param ServerRequestInterface $request
     * @param TokenInterface $authToken
     */
    public function __construct(ServerRequestInterface $request, protected TokenInterface $authToken)
    {
        parent::__construct($request);
    }

    /**
     * @return TokenInterface
     */
    public function getAuthToken(): TokenInterface
    {
        return $this->authToken;
    }
}