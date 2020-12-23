<?php

declare(strict_types=1);

namespace IA\Auth\User;

use InvalidArgumentException;

use function array_intersect;
use function array_map;
use function count;

class User implements UserInterface, EquatableInterface
{
    /**
     * User constructor.
     * @param string $username
     * @param string $email
     * @param string|null $password
     * @param array $roles
     * @param bool $enabled
     * @param bool $accountNonExpired
     * @param bool $credentialsNonExpired
     * @param bool $accountNonLocked
     * @param array $extraFields
     */
    public function __construct(
        protected string $username,
        protected string $email,
        protected ?string $password,
        protected array $roles = [],
        protected bool $enabled = true,
        protected bool $accountNonExpired = true,
        protected bool $credentialsNonExpired = true,
        protected bool $accountNonLocked = true,
        protected array $extraFields = []
    ) {
        if (empty($username)) {
            throw new InvalidArgumentException('The username cannot be empty.');
        }

        if (empty($email)) {
            throw new InvalidArgumentException('The email cannot be empty.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isEqualTo(UserInterface $user): bool
    {
        if (!$user instanceof self) {
            return false;
        }

        if ($this->getPassword() !== $user->getPassword()) {
            return false;
        }

        $currentRoles = array_map('strval', (array)$this->getRoles());
        $newRoles = array_map('strval', (array)$user->getRoles());
        $rolesChanged = count($currentRoles) !== count($newRoles)
            || count($currentRoles) !== count(array_intersect($currentRoles, $newRoles));

        if ($rolesChanged) {
            return false;
        }

        if ($this->getUsername() !== $user->getUsername()) {
            return false;
        }

        if ($this->getEmail() !== $user->getEmail()) {
            return false;
        }

        if ($this->isAccountNonExpired() !== $user->isAccountNonExpired()) {
            return false;
        }

        if ($this->isAccountNonLocked() !== $user->isAccountNonLocked()) {
            return false;
        }

        if ($this->isCredentialsNonExpired() !== $user->isCredentialsNonExpired()) {
            return false;
        }

        if ($this->isEnabled() !== $user->isEnabled()) {
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles(): array
    {
        return $this->roles;
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
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    /**
     * @param string $password
     */
    public function setPassword(string $password)
    {
        $this->password = $password;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
        $this->password = null;
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return $this->getUsername();
    }

    /**
     * @return bool
     */
    public function isAccountNonExpired(): bool
    {
        return $this->accountNonExpired;
    }

    /**
     * @return bool
     */
    public function isAccountNonLocked(): bool
    {
        return $this->accountNonLocked;
    }

    /**
     * @return bool
     */
    public function isCredentialsNonExpired(): bool
    {
        return $this->credentialsNonExpired;
    }

    /**
     * @return array
     */
    public function getExtraFields(): array
    {
        return $this->extraFields;
    }

    /**
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }
}