<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use DateTimeInterface;

interface PersistentTokenInterface
{
    /**
     * Returns the class of the user.
     *
     * @return string
     */
    public function getClass(): string;

    /**
     * Returns the username.
     *
     * @return string
     */
    public function getUsername(): string;

    /**
     * Returns the series.
     *
     * @return string
     */
    public function getSeries(): string;

    /**
     * Returns the token value.
     *
     * @return string
     */
    public function getTokenValue(): string;

    /**
     * Returns the time the token was last used.
     *
     * @return DateTimeInterface
     */
    public function getLastUsed(): DateTimeInterface;
}