<?php

declare(strict_types=1);

namespace IA\Auth\Encoder;

use IA\Auth\User\UserInterface;

interface UserPasswordEncoderInterface
{
    /**
     * Encodes the plain password.
     *
     * @param string $raw
     * @return string The encoded password
     */
    public function encode(string $raw): string;

    /**
     * @param UserInterface $user
     * @param string $raw
     * @return bool true if the password is valid, false otherwise
     */
    public function isValid(UserInterface $user, string $raw): bool;

    /**
     * Checks if an encoded password would benefit from rehashing.
     *
     * @param UserInterface $user
     * @return bool
     */
    public function needsRehash(UserInterface $user): bool;
}