<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use Exception;
use IA\Auth\Exception\AuthException;
use IA\Auth\Exception\CookieTheftException;
use IA\Auth\Exception\UserNotFoundException;
use IA\Auth\Token\TokenInterface;
use IA\Auth\User\UserInterface;
use Psr\Http\Message\ServerRequestInterface;

use function base64_decode;
use function base64_encode;
use function count;
use function hash_equals;
use function hash_hmac;
use function time;

/**
 * Concrete implementation of the RememberMeServicesInterface providing
 * remember-me capabilities without requiring a TokenProvider.
 */
class TokenBasedRememberMeServices extends AbstractRememberMeServices
{
    /**
     * {@inheritDoc}
     */
    protected function processAutoLoginCookie(ServerRequestInterface $request, array $cookieParts): UserInterface
    {
        if (4 !== count($cookieParts)) {
            throw new CookieTheftException('The cookie is invalid.');
        }

        [$class, $username, $expire, $hash] = $cookieParts;

        $expire = (int)$expire;

        if (false === $username = base64_decode($username, true)) {
            throw new CookieTheftException('$username contains a character from outside the base64 alphabet.');
        }
        try {
            $user = $this->userProvider->loadByUsername($username);
        } catch (Exception $e) {
            if (!$e instanceof AuthException) {
                $e = new UserNotFoundException($username, $e->getMessage(), $e->getCode(), $e);
            }

            throw $e;
        }

        if (true !== hash_equals($this->generateCookieHash($class, $username, $expire, $user->getPassword()), $hash)) {
            throw new CookieTheftException('The cookie\'s hash is invalid.');
        }

        if ($expire < time()) {
            throw new AuthException('The cookie has expired.');
        }

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    protected function onLoginSuccess(ServerRequestInterface $request, TokenInterface $token): ServerRequestInterface
    {
        $user = $token->getUser();
        $expire = time() + $this->options['expire'];
        $value = $this->generateCookieValue($user::class, $user->getUsername(), $expire, $user->getPassword());

        $this->cookieJar->add(
            $this->options['name'],
            $value,
            $expire,
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
     * Generates the cookie value.
     *
     * @param string $class
     * @param string $username
     * @param int $expire The Unix timestamp when the cookie expires
     * @param string|null $password The encoded password
     * @return string
     */
    protected function generateCookieValue(string $class, string $username, int $expire, ?string $password): string
    {
        // $username is encoded because it might contain COOKIE_DELIMITER,
        // we assume other values don't
        return $this->encodeCookie(
            [
                $class,
                base64_encode($username),
                $expire,
                $this->generateCookieHash($class, $username, $expire, $password),
            ]
        );
    }

    /**
     * Generates a hash for the cookie to ensure it is not being tampered with.
     *
     * @param string $class
     * @param string $username
     * @param int $expire The Unix timestamp when the cookie expires
     * @param string|null $password The encoded password
     * @return string
     */
    protected function generateCookieHash(string $class, string $username, int $expire, ?string $password): string
    {
        return hash_hmac(
            'sha256',
            $class.self::COOKIE_DELIMITER.$username.self::COOKIE_DELIMITER.$expire.self::COOKIE_DELIMITER.$password,
            $this->secret
        );
    }
}