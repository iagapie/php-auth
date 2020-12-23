<?php

declare(strict_types=1);

namespace IA\Auth\Passport;

use IA\Auth\Passport\Badge\UserBadge;
use IA\Auth\Passport\Credentials\CredentialsInterface;

class Passport implements UserPassportInterface
{
    use PassportTrait;
    use UserPassportTrait;

    /**
     * Passport constructor.
     * @param UserBadge $userBadge
     * @param CredentialsInterface $credentials
     * @param array $badges
     */
    public function __construct(UserBadge $userBadge, CredentialsInterface $credentials, array $badges = [])
    {
        $this->addBadge($userBadge);
        $this->addBadge($credentials);

        foreach ($badges as $badge) {
            $this->addBadge($badge);
        }
    }
}