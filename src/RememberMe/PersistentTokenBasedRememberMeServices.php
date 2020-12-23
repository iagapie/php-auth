<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use DateTimeImmutable;
use IA\Auth\Exception\AuthException;
use IA\Auth\Exception\CookieTheftException;
use IA\Auth\Token\TokenInterface;
use IA\Auth\User\UserInterface;
use IA\Auth\User\UserProviderInterface;
use IA\Cookie\CookieJarInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

use function base64_encode;
use function count;
use function hash_equals;
use function hash_hmac;
use function random_bytes;
use function str_starts_with;
use function time;

/**
 * Concrete implementation of the RememberMeServicesInterface which needs
 * an implementation of TokenProviderInterface for providing remember-me
 * capabilities.
 */
class PersistentTokenBasedRememberMeServices extends AbstractRememberMeServices
{
    protected const HASHED_TOKEN_PREFIX = 'sha256_';

    /**
     * @param TokenProviderInterface $tokenProvider
     * @param UserProviderInterface $userProvider
     * @param SessionInterface $session
     * @param CookieJarInterface $cookieJar
     * @param LoggerInterface $logger
     * @param string $secret
     * @param string $firewallName
     * @param array $options
     */
    public function __construct(
        protected TokenProviderInterface $tokenProvider,
        UserProviderInterface $userProvider,
        SessionInterface $session,
        CookieJarInterface $cookieJar,
        LoggerInterface $logger,
        string $secret,
        string $firewallName,
        array $options = []
    ) {
        parent::__construct($userProvider, $session, $cookieJar, $logger, $secret, $firewallName, $options);
    }

    /**
     * {@inheritdoc}
     */
    protected function cancelCookie(ServerRequestInterface $request): ServerRequestInterface
    {
        // Delete cookie on the client
        $request = parent::cancelCookie($request);

        // Delete cookie from the tokenProvider
        if (null !== ($cookie = ($request->getCookieParams()[$this->options['name']] ?? null))
            && 2 === count($parts = $this->decodeCookie($cookie))) {
            [$series] = $parts;
            $this->tokenProvider->deleteTokenBySeries($series);
        }

        return $request;
    }

    /**
     * {@inheritDoc}
     */
    protected function processAutoLoginCookie(ServerRequestInterface $request, array $cookieParts): UserInterface
    {
        if (2 !== count($cookieParts)) {
            throw new CookieTheftException('The cookie is invalid.');
        }

        [$series, $tokenValue] = $cookieParts;
        $persistentToken = $this->tokenProvider->loadTokenBySeries($series);

        if (!$this->isTokenValueValid($persistentToken, $tokenValue)) {
            throw new CookieTheftException('This token was already used. The account is possibly compromised.');
        }

        if ($persistentToken->getLastUsed()->getTimestamp() + $this->options['expire'] < time()) {
            throw new AuthException('The cookie has expired.');
        }

        $tokenValue = base64_encode(random_bytes(64));
        $this->tokenProvider->updateToken($series, $this->generateHash($tokenValue), new DateTimeImmutable());

        $this->cookieJar->add(
            $this->options['name'],
            $this->encodeCookie([$series, $tokenValue]),
            time() + $this->options['expire'],
            $this->options['path'],
            $this->options['domain'],
            null,
            $this->options['http_only'],
            false,
            $this->options['same_site']
        );

        return $this->userProvider->loadByUsername($persistentToken->getUsername());
    }

    /**
     * {@inheritDoc}
     */
    protected function onLoginSuccess(ServerRequestInterface $request, TokenInterface $token): ServerRequestInterface
    {
        $series = base64_encode(random_bytes(64));
        $tokenValue = base64_encode(random_bytes(64));

        $user = $token->getUser();

        $this->tokenProvider->createNewToken(
            new PersistentToken(
                $user::class,
                $user->getUsername(),
                $series,
                $this->generateHash($tokenValue),
                new DateTimeImmutable()
            )
        );

        $this->cookieJar->add(
            $this->options['name'],
            $this->encodeCookie([$series, $tokenValue]),
            time() + $this->options['expire'],
            $this->options['path'],
            $this->options['domain'],
            null,
            $this->options['http_only'],
            false,
            $this->options['same_site']
        );

        return $request;
    }

    /**
     * @param string $tokenValue
     * @return string
     */
    protected function generateHash(string $tokenValue): string
    {
        return self::HASHED_TOKEN_PREFIX.hash_hmac('sha256', $tokenValue, $this->secret);
    }

    /**
     * @param PersistentTokenInterface $persistentToken
     * @param string $tokenValue
     * @return bool
     */
    protected function isTokenValueValid(PersistentTokenInterface $persistentToken, string $tokenValue): bool
    {
        if (str_starts_with($persistentToken->getTokenValue(), self::HASHED_TOKEN_PREFIX)) {
            return hash_equals($persistentToken->getTokenValue(), $this->generateHash($tokenValue));
        }

        return hash_equals($persistentToken->getTokenValue(), $tokenValue);
    }
}