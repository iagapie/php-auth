<?php

declare(strict_types=1);

namespace IA\Auth\Encoder;

use IA\Auth\Exception\BadCredentialsException;

interface PasswordEncoderInterface
{
    /**
     * Encodes the raw password.
     *
     * @param string $raw
     * @return string The encoded password
     *
     * @throws BadCredentialsException If the raw password is invalid, e.g. excessively long
     */
    public function encode(string $raw): string;

    /**
     * Checks a raw password against an encoded password.
     *
     * @param string $encoded An encoded password
     * @param string $raw A raw password
     *
     * @return bool true if the password is valid, false otherwise
     */
    public function isValid(string $encoded, string $raw): bool;

    /**
     * Checks if an encoded password would benefit from rehashing.
     *
     * @param string $encoded
     * @return bool
     */
    public function needsRehash(string $encoded): bool;
}