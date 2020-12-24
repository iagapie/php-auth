<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Exception\AuthException;
use IA\Auth\Passport\Badge\UserBadge;
use IA\Auth\Passport\PassportInterface;
use IA\Auth\Passport\SelfValidatingPassport;
use IA\Auth\RememberMe\RememberMeServicesInterface;
use IA\Auth\Token\RememberMeToken;
use IA\Auth\Token\Storage\TokenStorageInterface;
use IA\Auth\Token\TokenInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class RememberMeAuth implements InteractiveAuthInterface
{
    /**
     * @var TokenInterface|null
     */
    protected ?TokenInterface $token = null;

    /**
     * @param RememberMeServicesInterface $rememberMeServices
     * @param TokenStorageInterface $tokenStorage
     * @param SessionInterface $session
     * @param string $secret
     */
    public function __construct(
        protected RememberMeServicesInterface $rememberMeServices,
        protected TokenStorageInterface $tokenStorage,
        protected SessionInterface $session,
        protected string $secret
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function createToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        return new RememberMeToken($passport->getUser(), $firewallName, $this->secret);
    }

    /**
     * {@inheritDoc}
     */
    public function supports(ServerRequestInterface $request): bool
    {
        // do not overwrite already stored tokens (i.e. from the session)
        if (null !== $this->tokenStorage->getToken()) {
            return false;
        }

        if (null !== $this->token) {
            return true;
        }

        $request = $this->rememberMeServices->autoLogin($request);

        $this->token = $request->getAttribute(RememberMeServicesInterface::ATTR_REMEMBER_ME_TOKEN);

        return null !== $this->token;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request): ServerRequestInterface
    {
        if (null === $this->token) {
            throw new LogicException('No remember me token is set.');
        }

        $passport = new SelfValidatingPassport(new UserBadge($this->token->getUsername(), [$this->token, 'getUser']));

        return $request->withAttribute(static::ATTR_PASSPORT, $passport);
    }

    /**
     * {@inheritDoc}
     */
    public function onSuccess(
        ServerRequestInterface $request,
        TokenInterface $token,
        string $firewallName
    ): ServerRequestInterface {
        $this->session->remove(AuthManagerInterface::ATTR_AUTH_USERNAME.$firewallName);

        return $request; // let the original request continue
    }

    /**
     * {@inheritDoc}
     */
    public function onFailure(ServerRequestInterface $request, AuthException $exception): ServerRequestInterface
    {
        return $request; // $this->rememberMeServices->loginFail($request, $exception);
    }

    /**
     * {@inheritDoc}
     */
    public function isInteractive(): bool
    {
        return true;
    }
}