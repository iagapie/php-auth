<?php

declare(strict_types=1);

namespace IA\Auth\User;

use IA\Auth\Exception\UserNotFoundException;

interface UserProviderInterface
{
    /**
     * Loads the user for the given value (username or email).
     *
     * This method must throw UserNotFoundException if the user is not
     * found.
     *
     * @param string $value
     * @return UserInterface
     * @throws UserNotFoundException if the user is not found
     */
    public function load(string $value): UserInterface;

    /**
     * Loads the user for the given username.
     *
     * This method must throw UserNotFoundException if the user is not
     * found.
     *
     * @param string $username
     * @return UserInterface
     * @throws UserNotFoundException if the user is not found
     */
    public function loadByUsername(string $username): UserInterface;

    /**
     * Loads the user for the given email.
     *
     * This method must throw UserNotFoundException if the user is not
     * found.
     *
     * @param string $email
     * @return UserInterface
     * @throws UserNotFoundException if the user is not found
     */
    public function loadByEmail(string $email): UserInterface;

    /**
     * Refreshes the user.
     *
     * It is up to the implementation to decide if the user data should be
     * totally reloaded (e.g. from the database), or if the UserInterface
     * object can just be merged into some internal array of users / identity
     * map.
     *
     * @param UserInterface $user
     * @return UserInterface
     *
     * @throws UserNotFoundException if the user is not found
     */
    public function refresh(UserInterface $user): UserInterface;
}