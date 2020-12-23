<?php

declare(strict_types=1);

namespace IA\Auth\Token;

use IA\Auth\User\UserInterface;

class SwitchUserToken extends UsernamePasswordToken
{
    /**
     * @param string|UserInterface $user The username (like a nickname, email address, etc.), or a UserInterface instance or an object implementing a __toString method
     * @param mixed $credentials This usually is the password of the user
     * @param string $firewallName
     * @param array $roles
     * @param TokenInterface $originalToken
     * @param string|null $originatedFromUri The URI where was the user at the switch
     */
    public function __construct(
        string|UserInterface $user,
        mixed $credentials,
        string $firewallName,
        array $roles,
        protected TokenInterface $originalToken,
        protected ?string $originatedFromUri = null
    ) {
        parent::__construct($user, $credentials, $firewallName, $roles);
    }

    /**
     * @return TokenInterface
     */
    public function getOriginalToken(): TokenInterface
    {
        return $this->originalToken;
    }

    /**
     * @return string|null
     */
    public function getOriginatedFromUri(): ?string
    {
        return $this->originatedFromUri;
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [$this->originalToken, $this->originatedFromUri, parent::__serialize()];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
        [$this->originalToken, $this->originatedFromUri, $parentData] = $data;

        parent::__unserialize($parentData);
    }
}