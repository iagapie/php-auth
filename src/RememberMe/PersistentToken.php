<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use DateTimeInterface;

class PersistentToken implements PersistentTokenInterface
{
    /**
     * @param string $class
     * @param string $username
     * @param string $series
     * @param string $tokenValue
     * @param DateTimeInterface $lastUsed
     */
    public function __construct(
        protected string $class,
        protected string $username,
        protected string $series,
        protected string $tokenValue,
        protected DateTimeInterface $lastUsed
    ) {
        if (empty($class)) {
            throw new \InvalidArgumentException('$class must not be empty.');
        }

        if (empty($username)) {
            throw new \InvalidArgumentException('$username must not be empty.');
        }

        if (empty($series)) {
            throw new \InvalidArgumentException('$series must not be empty.');
        }

        if (empty($tokenValue)) {
            throw new \InvalidArgumentException('$tokenValue must not be empty.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getClass(): string
    {
        return $this->class;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * {@inheritdoc}
     */
    public function getSeries(): string
    {
        return $this->series;
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenValue(): string
    {
        return $this->tokenValue;
    }

    /**
     * {@inheritdoc}
     */
    public function getLastUsed(): DateTimeInterface
    {
        return $this->lastUsed;
    }
}