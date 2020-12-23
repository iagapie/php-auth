<?php

declare(strict_types=1);

namespace IA\Auth\Event;

use IA\Auth\AuthInterface;
use IA\Auth\Passport\PassportInterface;
use Symfony\Contracts\EventDispatcher\Event;

class CheckPassportEvent extends Event
{
    /**
     * @param AuthInterface $auth
     * @param PassportInterface $passport
     */
    public function __construct(protected AuthInterface $auth, protected PassportInterface $passport)
    {
    }

    /**
     * @return AuthInterface
     */
    public function getAuth(): AuthInterface
    {
        return $this->auth;
    }

    /**
     * @return PassportInterface
     */
    public function getPassport(): PassportInterface
    {
        return $this->passport;
    }
}