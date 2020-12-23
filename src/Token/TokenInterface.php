<?php

declare(strict_types=1);

namespace IA\Auth\Token;

use IA\Auth\User\UserInterface;
use InvalidArgumentException;

interface TokenInterface extends \Stringable
{
    /**
     * Returns the user roles.
     *
     * @return string[] The associated roles
     */
    public function getRoles(): array;

    /**
     * Returns the user credentials.
     *
     * @return mixed The user credentials
     */
    public function getCredentials(): mixed;

    /**
     * Returns a user representation.
     *
     * @return string|UserInterface
     *
     * @see AbstractToken::setUser()
     */
    public function getUser(): string|UserInterface;

    /**
     * Sets the user in the token.
     *
     * The user can be a UserInterface instance, or an object implementing
     * a __toString method or the username as a regular string.
     *
     * @param string|UserInterface $user
     *
     * @throws InvalidArgumentException
     */
    public function setUser(string|UserInterface $user): void;

    /**
     * Returns the username.
     *
     * @return string
     */
    public function getUsername(): string;

    /**
     * Returns whether the user is authenticated or not.
     *
     * @return bool true if the token has been authenticated, false otherwise
     */
    public function isAuthenticated(): bool;

    /**
     * Sets the authenticated flag.
     * @param bool $authenticated
     */
    public function setAuthenticated(bool $authenticated): void;

    /**
     * Removes sensitive information from the token.
     */
    public function eraseCredentials(): void;

    /**
     * Returns the token attributes.
     *
     * @return array The token attributes
     */
    public function getAttributes(): array;

    /**
     * Sets the token attributes.
     *
     * @param array $attributes The token attributes
     */
    public function setAttributes(array $attributes): void;

    /**
     * Returns true if the attribute exists.
     *
     * @param string $name
     * @return bool true if the attribute exists, false otherwise
     */
    public function hasAttribute(string $name): bool;

    /**
     * Returns an attribute value.
     *
     * @param string $name
     * @return mixed The attribute value
     *
     * @throws InvalidArgumentException When attribute doesn't exist for this token
     */
    public function getAttribute(string $name): mixed;

    /**
     * Sets an attribute.
     *
     * @param string $name
     * @param mixed $value The attribute value
     */
    public function setAttribute(string $name, mixed $value): void;

    /**
     * Returns all the necessary state of the object for serialization purposes.
     */
    public function __serialize(): array;

    /**
     * Restores the object state from an array given by __serialize().
     * @param array $data
     */
    public function __unserialize(array $data): void;
}