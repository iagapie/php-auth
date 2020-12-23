<?php

declare(strict_types=1);

namespace IA\Auth\Event;

use IA\Auth\AuthInterface;
use IA\Auth\Exception\AuthException;
use IA\Auth\Passport\PassportInterface;
use Psr\Http\Message\ServerRequestInterface;

class LoginFailureEvent extends AuthEvent
{
    /**
     * @param ServerRequestInterface $request
     * @param AuthInterface $auth
     * @param AuthException $exception
     * @param string $firewallName
     */
    public function __construct(
        ServerRequestInterface $request,
        protected AuthInterface $auth,
        protected AuthException $exception,
        protected string $firewallName
    ) {
        parent::__construct($request);
    }

    /**
     * @return AuthException
     */
    public function getException(): AuthException
    {
        return $this->exception;
    }

    /**
     * @return AuthInterface
     */
    public function getAuth(): AuthInterface
    {
        return $this->auth;
    }

    /**
     * @return string
     */
    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    /**
     * @return PassportInterface|null
     */
    public function getPassport(): ?PassportInterface
    {
        return $this->request->getAttribute(AuthInterface::ATTR_PASSPORT);
    }
}