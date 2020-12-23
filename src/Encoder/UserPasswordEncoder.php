<?php

declare(strict_types=1);

namespace IA\Auth\Encoder;

use IA\Auth\User\UserInterface;

class UserPasswordEncoder implements UserPasswordEncoderInterface
{
    /**
     * UserPasswordEncoder constructor.
     * @param PasswordEncoderInterface $encoder
     */
    public function __construct(protected PasswordEncoderInterface $encoder)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function encode(string $raw): string
    {
        return $this->encoder->encode($raw);
    }

    /**
     * {@inheritdoc}
     */
    public function isValid(UserInterface $user, string $raw): bool
    {
        if (null === $user->getPassword()) {
            return false;
        }

        return $this->encoder->isValid($user->getPassword(), $raw);
    }

    /**
     * {@inheritdoc}
     */
    public function needsRehash(UserInterface $user): bool
    {
        if (null === $user->getPassword()) {
            return false;
        }

        return $this->encoder->needsRehash($user->getPassword());
    }
}