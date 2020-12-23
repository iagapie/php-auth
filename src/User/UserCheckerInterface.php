<?php

declare(strict_types=1);

namespace IA\Auth\User;

use IA\Auth\Exception\AccountStatusException;

interface UserCheckerInterface
{
    /**
     * Checks the user account before authentication.
     *
     * @param UserInterface $user
     * @throws AccountStatusException
     */
    public function checkPreAuth(UserInterface $user): void;

    /**
     * Checks the user account after authentication.
     *
     * @param UserInterface $user
     * @throws AccountStatusException
     */
    public function checkPostAuth(UserInterface $user): void;
}