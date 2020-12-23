<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Token\NullToken;
use IA\Auth\Token\Storage\TokenStorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AuthMiddleware implements MiddlewareInterface
{
    /**
     * @param AuthManagerInterface $authManager
     * @param TokenStorageInterface $tokenStorage
     */
    public function __construct(
        protected AuthManagerInterface $authManager,
        protected TokenStorageInterface $tokenStorage
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->isAuthenticated()) {
            return $handler->handle($request);
        }

        $request = $this->authManager->authenticate($request);

        if (null === ($response = $request->getAttribute(AuthInterface::ATTR_RESPONSE))) {
            $response = $handler->handle($request);
        }

        return $response;
    }

    /**
     * @return bool
     */
    protected function isAuthenticated(): bool
    {
        return $this->tokenStorage->getToken()?->isAuthenticated()
            && !$this->tokenStorage->getToken() instanceof NullToken;
    }
}