<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use Exception;
use IA\Auth\Token\TokenInterface;
use Psr\Http\Message\ServerRequestInterface;

interface RememberMeServicesInterface
{
    public const ATTR_REMEMBER_ME_TOKEN = '__AUTH_REMEMBER_ME_TOKEN__';

    /**
     * Deletes the cookie.
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    public function logout(ServerRequestInterface $request): ServerRequestInterface;

    /**
     * This method will be called whenever the TokenStorage does not contain
     * a TokenInterface object and the framework wishes to provide an implementation
     * with an opportunity to authenticate the request using remember-me capabilities.
     *
     * No attempt whatsoever is made to determine whether the browser has requested
     * remember-me services or presented a valid cookie. Any and all such determinations
     * are left to the implementation of this method.
     *
     * If a browser has presented an unauthorised cookie for whatever reason,
     * make sure to throw an AuthException as this will consequentially
     * result in a call to loginFail() and therefore an invalidation of the cookie.
     *
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    public function autoLogin(ServerRequestInterface $request): ServerRequestInterface;

    /**
     * Called whenever an interactive authentication attempt is successful
     * (e.g. a form login).
     *
     * An implementation may always set a remember-me cookie in the Response,
     * although this is not recommended.
     *
     * Instead, implementations should typically look for a request parameter
     * (such as a HTTP POST parameter) that indicates the browser has explicitly
     * requested for the authentication to be remembered.
     * @param ServerRequestInterface $request
     * @param TokenInterface $token
     * @return ServerRequestInterface
     */
    public function loginSuccess(ServerRequestInterface $request, TokenInterface $token): ServerRequestInterface;

    /**
     * Called whenever an interactive authentication attempt was made, but the
     * credentials supplied by the user were missing or otherwise invalid.
     *
     * This method needs to take care of invalidating the cookie.
     * @param ServerRequestInterface $request
     * @param Exception|null $exception
     * @return ServerRequestInterface
     */
    public function loginFail(ServerRequestInterface $request, Exception $exception = null): ServerRequestInterface;
}