<?php

declare(strict_types=1);

namespace IA\Auth\Token;

use IA\Auth\User\UserInterface;
use InvalidArgumentException;

class PostAuthenticationToken extends AbstractToken
{
    /**
     * PostAuthenticationToken constructor.
     * @param UserInterface $user
     * @param string $firewallName
     * @param array $roles
     */
    public function __construct(UserInterface $user, protected string $firewallName, array $roles = [])
    {
        parent::__construct($roles);

        if ('' === $firewallName) {
            throw new InvalidArgumentException('$firewallName must not be empty.');
        }

        $this->setUser($user);

        // this token is meant to be used after authentication success, so it is always authenticated
        // you could set it as non authenticated later if you need to
        $this->setAuthenticated(true);
    }

    /**
     * This is meant to be only an authenticated token, where credentials
     * have already been used and are thus cleared.
     *
     * {@inheritdoc}
     */
    public function getCredentials(): mixed
    {
        return [];
    }

    /**
     * @return string
     */
    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [$this->firewallName, parent::__serialize()];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
        [$this->firewallName, $parentData] = $data;

        parent::__unserialize($parentData);
    }
}