<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Passport\Badge\BadgeInterface;
use IA\Auth\User\UserInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthManagerInterface
{
    public const ATTR_AUTH_USERNAME = '__auth_username.';

    /**
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    public function authenticate(ServerRequestInterface $request): ServerRequestInterface;

    /**
     * Convenience method to programmatically login a user
     *
     * @param ServerRequestInterface $request
     * @param AuthInterface $auth
     * @param UserInterface $user
     * @param BadgeInterface[] $badges
     * @return ServerRequestInterface
     */
    public function authenticateUser(
        ServerRequestInterface $request,
        AuthInterface $auth,
        UserInterface $user,
        array $badges = []
    ): ServerRequestInterface;

    /**
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    public function logout(ServerRequestInterface $request): ServerRequestInterface;
}