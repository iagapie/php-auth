<?php

declare(strict_types=1);

namespace IA\Auth\Token;

use IA\Auth\User\UserInterface;
use BadMethodCallException;

final class NullToken implements TokenInterface
{
    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(): mixed
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function getUser(): string|UserInterface
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function setUser(UserInterface|string $user): void
    {
        throw new BadMethodCallException('Cannot set user on a NullToken.');
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername(): string
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthenticated(): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated(bool $authenticated): void
    {
        throw new BadMethodCallException('Cannot change authentication state of NullToken.');
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getAttributes(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function setAttributes(array $attributes): void
    {
        throw new BadMethodCallException('Cannot set attributes of NullToken.');
    }

    /**
     * {@inheritdoc}
     */
    public function hasAttribute(string $name): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getAttribute(string $name): mixed
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function setAttribute(string $name, mixed $value): void
    {
        throw new BadMethodCallException('Cannot add attribute to NullToken.');
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
    }
}