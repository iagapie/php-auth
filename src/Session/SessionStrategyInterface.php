<?php

declare(strict_types=1);

namespace IA\Auth\Session;

use IA\Auth\Token\TokenInterface;
use Psr\Http\Message\ServerRequestInterface;

interface SessionStrategyInterface
{
    /**
     * This performs any necessary changes to the session.
     *
     * This method should be called before the TokenStorage is populated with a
     * Token. It should be used by authentication listeners when a session is used.
     *
     * @param ServerRequestInterface $request
     * @param TokenInterface $token
     * @return ServerRequestInterface
     */
    public function onAuthentication(ServerRequestInterface $request, TokenInterface $token): ServerRequestInterface;
}