<?php

declare(strict_types=1);

namespace IA\Auth\Passport;

use IA\Auth\User\UserInterface;

interface UserPassportInterface extends PassportInterface
{
    /**
     * @return UserInterface
     */
    public function getUser(): UserInterface;
}