<?php

declare(strict_types=1);

namespace IA\Auth\Passport;

use IA\Auth\Passport\Badge\UserBadge;
use IA\Auth\User\UserInterface;
use LogicException;

trait UserPassportTrait
{
    /**
     * @return UserInterface
     */
    public function getUser(): UserInterface
    {
        if (!$this->hasBadge(UserBadge::class)) {
            throw new LogicException('Cannot get the Security user, no username or UserBadge configured for this passport.');
        }

        return $this->getBadge(UserBadge::class)->getUser();
    }
}