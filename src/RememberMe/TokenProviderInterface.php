<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use IA\Auth\Exception\TokenNotFoundException;
use DateTimeInterface;

interface TokenProviderInterface
{
    /**
     * Loads the active token for the given series.
     *
     * @param string $series
     * @return PersistentTokenInterface
     * @throws TokenNotFoundException if the token is not found
     */
    public function loadTokenBySeries(string $series): PersistentTokenInterface;

    /**
     * Deletes all tokens belonging to series.
     * @param string $series
     */
    public function deleteTokenBySeries(string $series): void;

    /**
     * Updates the token according to this data.
     *
     * @param string $series
     * @param string $tokenValue
     * @param DateTimeInterface $lastUsed
     * @throws TokenNotFoundException if the token is not found
     */
    public function updateToken(string $series, string $tokenValue, DateTimeInterface $lastUsed): void;

    /**
     * Creates a new token.
     * @param PersistentTokenInterface $token
     */
    public function createNewToken(PersistentTokenInterface $token): void;
}