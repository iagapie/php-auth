<?php

declare(strict_types=1);

namespace IA\Auth\Token;

use IA\Auth\User\UserInterface;
use InvalidArgumentException;
use LogicException;

use function count;

class UsernamePasswordToken extends AbstractToken
{
    /**
     * UsernamePasswordToken constructor.
     * @param string|UserInterface $user
     * @param mixed $credentials
     * @param string $firewallName
     * @param array $roles
     */
    public function __construct(
        string|UserInterface $user,
        protected mixed $credentials,
        protected string $firewallName,
        array $roles = []
    ) {
        parent::__construct($roles);

        if ('' === $firewallName) {
            throw new InvalidArgumentException('$firewallName must not be empty.');
        }

        $this->setUser($user);

        parent::setAuthenticated(count($roles) > 0);
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
    public function getCredentials(): mixed
    {
        return $this->credentials;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
        parent::eraseCredentials();

        $this->credentials = null;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated(bool $authenticated): void
    {
        if ($authenticated) {
            throw new LogicException('Cannot set this token to trusted after instantiation.');
        }

        parent::setAuthenticated(false);
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [$this->credentials, $this->firewallName, parent::__serialize()];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
        [$this->credentials, $this->firewallName, $parentData] = $data;

        parent::__unserialize($parentData);
    }
}