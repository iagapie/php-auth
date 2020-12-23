<?php

declare(strict_types=1);

namespace IA\Auth\Token;

use IA\Auth\User\UserInterface;
use InvalidArgumentException;
use LogicException;

class RememberMeToken extends AbstractToken
{
    /**
     * RememberMeToken constructor.
     * @param UserInterface $user
     * @param string $firewallName
     * @param string $secret
     */
    public function __construct(UserInterface $user, protected string $firewallName, protected string $secret)
    {
        parent::__construct($user->getRoles());

        if (empty($secret)) {
            throw new InvalidArgumentException('$secret must not be empty.');
        }

        if (empty($firewallName)) {
            throw new InvalidArgumentException('$firewallName must not be empty.');
        }

        $this->setUser($user);

        parent::setAuthenticated(true);
    }

    /**
     * @return string
     */
    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated(bool $authenticated): void
    {
        if ($authenticated) {
            throw new LogicException('You cannot set this token to authenticated after creation.');
        }

        parent::setAuthenticated(false);
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
    public function __serialize(): array
    {
        return [$this->secret, $this->firewallName, parent::__serialize()];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
        [$this->secret, $this->firewallName, $parentData] = $data;

        parent::__unserialize($parentData);
    }
}