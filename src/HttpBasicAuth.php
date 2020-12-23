<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Exception\AuthException;
use IA\Auth\Passport\Badge\UserBadge;
use IA\Auth\Passport\Credentials\PasswordCredentials;
use IA\Auth\Passport\Passport;
use IA\Auth\Passport\PassportInterface;
use IA\Auth\Token\TokenInterface;
use IA\Auth\Token\UsernamePasswordToken;
use IA\Auth\User\UserProviderInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

class HttpBasicAuth implements AuthInterface
{
    /**
     * @param string $realmName
     * @param UserProviderInterface $userProvider
     * @param ResponseFactoryInterface $responseFactory
     * @param LoggerInterface $logger
     * @param string $userLoadMethod
     */
    public function __construct(
        protected string $realmName,
        protected UserProviderInterface $userProvider,
        protected ResponseFactoryInterface $responseFactory,
        protected LoggerInterface $logger,
        protected string $userLoadMethod = 'load'
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function createToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        return new UsernamePasswordToken($passport->getUser(), null, $firewallName, $passport->getUser()->getRoles());
    }

    /**
     * {@inheritDoc}
     */
    public function supports(ServerRequestInterface $request): bool
    {
        return $request->hasHeader('PHP_AUTH_USER');
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request): ServerRequestInterface
    {
        $username = $request->getHeaderLine('PHP_AUTH_USER');
        $password = $request->getHeaderLine('PHP_AUTH_PW');

        $passport = new Passport(
            new UserBadge($username, fn(string $username) => $this->userProvider->{$this->userLoadMethod}($username)),
            new PasswordCredentials($password)
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
        $this->logger->info(
            'Basic authentication failed for user.',
            ['username' => $request->getHeaderLine('PHP_AUTH_USER'), 'exception' => $exception]
        );

        $response = $this->responseFactory
            ->createResponse(401)
            ->withHeader('WWW-Authenticate', \sprintf('Basic realm="%s"', $this->realmName));

        return $request->withAttribute(static::ATTR_RESPONSE, $response);
    }
}