<?php

declare(strict_types=1);

namespace IA\Auth\Event;

use IA\Auth\AuthInterface;
use IA\Auth\Passport\PassportInterface;
use IA\Auth\Passport\UserPassportInterface;
use IA\Auth\Token\TokenInterface;
use IA\Auth\User\UserInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;

use function sprintf;

class LoginSuccessEvent extends AuthEvent
{
    /**
     * @param ServerRequestInterface $request
     * @param AuthInterface $auth
     * @param TokenInterface $authToken
     * @param string $firewallName
     */
    public function __construct(
        ServerRequestInterface $request,
        protected AuthInterface $auth,
        protected TokenInterface $authToken,
        protected string $firewallName
    ) {
        parent::__construct($request);
    }

    /**
     * @return UserInterface
     */
    public function getUser(): UserInterface
    {
        if (!$this->getPassport() instanceof UserPassportInterface) {
            throw new LogicException(
                sprintf(
                    'Cannot call "%s" as the authenticator ("%s") did not set a user.',
                    __METHOD__,
                    $this->auth::class
                )
            );
        }

        return $this->getPassport()->getUser();
    }


    /**
     * @return AuthInterface
     */
    public function getAuth(): AuthInterface
    {
        return $this->auth;
    }

    /**
     * @return PassportInterface
     */
    public function getPassport(): PassportInterface
    {
        return $this->request->getAttribute(AuthInterface::ATTR_PASSPORT);
    }

    /**
     * @return TokenInterface
     */
    public function getAuthToken(): TokenInterface
    {
        return $this->authToken;
    }

    /**
     * @return string
     */
    public function getFirewallName(): string
    {
        return $this->firewallName;
    }
}