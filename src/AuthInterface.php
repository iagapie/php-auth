<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Exception\AuthException;
use IA\Auth\Passport\PassportInterface;
use IA\Auth\Token\TokenInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthInterface
{
    public const ATTR_RESPONSE = '__AUTH_RESPONSE__';
    public const ATTR_PASSPORT = '__AUTH_PASSPORT__';

    /**
     * Create an authenticated token for the given user.
     *
     * @param PassportInterface $passport The passport returned from authenticate()
     * @param string $firewallName
     * @return TokenInterface
     */
    public function createToken(PassportInterface $passport, string $firewallName): TokenInterface;

    /**
     * Does the authenticator support the given Request?
     *
     * If this returns false, the authenticator will be skipped.
     *
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function supports(ServerRequestInterface $request): bool;

    /**
     * Create a passport for the current request.
     *
     * The passport contains the user, credentials and any additional information
     * that has to be checked by the Authentication system. For example, a login
     * form AuthInterface will probably return a passport containing the user, the
     * presented password and the CSRF token value.
     *
     * You may throw any AuthException in this method in case of error (e.g.
     * a UserNotFoundException when the user cannot be found).
     *
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     * @throws AuthException
     */
    public function authenticate(ServerRequestInterface $request): ServerRequestInterface;

    /**
     * Called when authentication executed and was successful!
     *
     * This should return the ServerRequestInterface with Response attribute set, like a
     * Response with Location header to the last page they visited.
     *
     * If you return ServerRequestInterface without Response attribute, the current request will continue,
     * and the user will be authenticated. This makes sense, for example, with an API.
     * @param ServerRequestInterface $request
     * @param TokenInterface $token
     * @param string $firewallName
     * @return ServerRequestInterface
     */
    public function onSuccess(
        ServerRequestInterface $request,
        TokenInterface $token,
        string $firewallName
    ): ServerRequestInterface;

    /**
     * Called when authentication executed, but failed (e.g. wrong username password).
     *
     * This should return the ServerRequestInterface with Response attribute set, like a
     * Response with Location header to the login page or a 403 response.
     *
     * If you return ServerRequestInterface without Response attribute, the request will continue,
     * but the user will not be authenticated. This is probably not what you want to do.
     * @param ServerRequestInterface $request
     * @param AuthException $exception
     * @return ServerRequestInterface
     */
    public function onFailure(
        ServerRequestInterface $request,
        AuthException $exception
    ): ServerRequestInterface;
}