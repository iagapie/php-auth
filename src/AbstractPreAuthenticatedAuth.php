<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Exception\AuthException;
use IA\Auth\Exception\BadCredentialsException;
use IA\Auth\Passport\Badge\PreAuthenticatedUserBadge;
use IA\Auth\Passport\Badge\UserBadge;
use IA\Auth\Passport\PassportInterface;
use IA\Auth\Passport\SelfValidatingPassport;
use IA\Auth\Token\PreAuthenticatedToken;
use IA\Auth\Token\Storage\TokenStorageInterface;
use IA\Auth\Token\TokenInterface;
use IA\Auth\User\UserProviderInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

abstract class AbstractPreAuthenticatedAuth implements InteractiveAuthInterface
{
    /**
     * @param UserProviderInterface $userProvider
     * @param TokenStorageInterface $tokenStorage
     * @param LoggerInterface $logger
     * @param string $firewallName
     * @param string $userLoadMethod
     */
    public function __construct(
        protected UserProviderInterface $userProvider,
        protected TokenStorageInterface $tokenStorage,
        protected LoggerInterface $logger,
        protected string $firewallName,
        protected string $userLoadMethod = 'loadByUsername'
    ) {
    }

    /**
     * Returns the username of the pre-authenticated user.
     *
     * This authenticator is skipped if null is returned or a custom
     * BadCredentialsException is thrown.
     *
     * @param ServerRequestInterface $request
     * @return string|null
     */
    abstract protected function extractUsername(ServerRequestInterface $request): ?string;

    /**
     * {@inheritDoc}
     */
    public function createToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        return new PreAuthenticatedToken($passport->getUser(), null, $firewallName, $passport->getUser()->getRoles());
    }

    /**
     * {@inheritDoc}
     */
    public function supports(ServerRequestInterface $request): bool
    {
        try {
            $username = $this->extractUsername($request);
        } catch (BadCredentialsException $e) {
            $this->clearToken($e);

            $this->logger->debug(
                'Skipping pre-authenticated authenticator as a BadCredentialsException is thrown.',
                ['exception' => $e, 'authenticator' => static::class]
            );

            return false;
        }

        if (empty($username)) {
            $this->logger->debug(
                'Skipping pre-authenticated authenticator no username could be extracted.',
                ['authenticator' => static::class]
            );

            return false;
        }

        return true;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request): ServerRequestInterface
    {
        $passport = new SelfValidatingPassport(
            new UserBadge(
                $this->extractUsername($request),
                fn (string $username) => $this->userProvider->{$this->userLoadMethod}($username)
            ), [new PreAuthenticatedUserBadge()]
        );

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
        return $request;
    }

    /**
     * {@inheritDoc}
     */
    public function onFailure(ServerRequestInterface $request, AuthException $exception): ServerRequestInterface
    {
        $this->clearToken($exception);

        return $request;
    }

    /**
     * {@inheritDoc}
     */
    public function isInteractive(): bool
    {
        return true;
    }

    /**
     * @param AuthException $exception
     */
    protected function clearToken(AuthException $exception): void
    {
        $token = $this->tokenStorage->getToken();

        if ($token instanceof PreAuthenticatedToken && $this->firewallName === $token->getFirewallName()) {
            $this->tokenStorage->setToken();

            $this->logger->info('Cleared pre-authenticated token due to an exception.', ['exception' => $exception]);
        }
    }
}