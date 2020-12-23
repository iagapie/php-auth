<?php

declare(strict_types=1);

namespace IA\Auth\Passport;

use IA\Auth\Passport\Badge\UserBadge;

class SelfValidatingPassport implements UserPassportInterface
{
    use PassportTrait;
    use UserPassportTrait;

    /**
     * SelfValidatingPassport constructor.
     * @param UserBadge $userBadge
     * @param array $badges
     */
    public function __construct(UserBadge $userBadge, array $badges = [])
    {
        $this->addBadge($userBadge);

        foreach ($badges as $badge) {
            $this->addBadge($badge);
        }
    }
}