<?php

declare(strict_types=1);

namespace IA\Auth\Token;

use IA\Auth\User\EquatableInterface;
use IA\Auth\User\UserInterface;
use BadMethodCallException;
use InvalidArgumentException;

use function array_intersect;
use function array_key_exists;
use function array_map;
use function array_values;
use function count;
use function implode;
use function json_encode;
use function sprintf;
use function strrpos;
use function substr;

abstract class AbstractToken implements TokenInterface
{
    /**
     * @var string|UserInterface|null
     */
    protected string|UserInterface|null $user = null;

    /**
     * @var bool
     */
    protected bool $authenticated = false;

    /**
     * @var array
     */
    protected array $attributes = [];

    /**
     * AbstractToken constructor.
     * @param string[] $roles
     */
    public function __construct(protected array $roles = [])
    {
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        $class = static::class;
        $class = substr($class, strrpos($class, '\\') + 1);

        return sprintf(
            '%s(user="%s", authenticated=%s, roles="%s")',
            $class,
            $this->getUsername(),
            json_encode($this->authenticated),
            implode(', ', array_values($this->roles))
        );
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
    public function getUser(): string|UserInterface
    {
        return $this->user;
    }

    /**
     * {@inheritdoc}
     */
    public function setUser(UserInterface|string $user): void
    {
        if (null === $this->user) {
            $changed = false;
        } elseif ($this->user instanceof UserInterface) {
            if (!$user instanceof UserInterface) {
                $changed = true;
            } else {
                $changed = $this->hasUserChanged($user);
            }
        } elseif ($user instanceof UserInterface) {
            $changed = true;
        } else {
            $changed = (string)$this->user !== (string)$user;
        }

        if ($changed) {
            $this->setAuthenticated(false);
        }

        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername(): string
    {
        if ($this->user instanceof UserInterface) {
            return $this->user->getUsername();
        }

        return (string)$this->user;
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthenticated(): bool
    {
        return $this->authenticated;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated(bool $authenticated): void
    {
        $this->authenticated = $authenticated;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials(): void
    {
        if ($this->getUser() instanceof UserInterface) {
            $this->getUser()->eraseCredentials();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * {@inheritdoc}
     */
    public function setAttributes(array $attributes): void
    {
        $this->attributes = $attributes;
    }

    /**
     * {@inheritdoc}
     */
    public function hasAttribute(string $name): bool
    {
        return array_key_exists($name, $this->attributes);
    }

    /**
     * {@inheritdoc}
     */
    public function getAttribute(string $name): mixed
    {
        if (!array_key_exists($name, $this->attributes)) {
            throw new InvalidArgumentException(sprintf('This token has no "%s" attribute.', $name));
        }

        return $this->attributes[$name];
    }

    /**
     * {@inheritdoc}
     */
    public function setAttribute(string $name, mixed $value): void
    {
        $this->attributes[$name] = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [$this->user, $this->authenticated, null, $this->attributes, $this->roles];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
        [$this->user, $this->authenticated, , $this->attributes, $this->roles] = $data;
    }

    /**
     * @param UserInterface $user
     * @return bool
     */
    private function hasUserChanged(UserInterface $user): bool
    {
        if (!($this->user instanceof UserInterface)) {
            throw new BadMethodCallException(
                'Method "hasUserChanged" should be called when current user class is instance of "UserInterface".'
            );
        }

        if ($this->user instanceof EquatableInterface) {
            return !(bool)$this->user->isEqualTo($user);
        }

        if ($this->user->getPassword() !== $user->getPassword()) {
            return true;
        }

        $userRoles = array_map('strval', (array)$user->getRoles());

        if (count($userRoles) !== count($this->getRoles())
            || count($userRoles) !== count(array_intersect($userRoles, $this->getRoles()))) {
            return true;
        }

        if ($this->user->getUsername() !== $user->getUsername()) {
            return true;
        }

        return false;
    }
}