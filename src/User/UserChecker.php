<?php

declare(strict_types=1);

namespace IA\Auth\User;

use IA\Auth\Exception\AccountExpiredException;
use IA\Auth\Exception\CredentialsExpiredException;
use IA\Auth\Exception\DisabledException;
use IA\Auth\Exception\LockedException;

class UserChecker implements UserCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkPreAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            return;
        }

        if (!$user->isAccountNonLocked()) {
            throw new LockedException($user);
        }

        if (!$user->isEnabled()) {
            throw new DisabledException($user);
        }

        if (!$user->isAccountNonExpired()) {
            throw new AccountExpiredException($user);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkPostAuth(UserInterface $user): void
    {
        if (!$user instanceof User) {
            return;
        }

        if (!$user->isCredentialsNonExpired()) {
            throw new CredentialsExpiredException($user);
        }
    }
}