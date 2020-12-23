<?php

declare(strict_types=1);

namespace IA\Auth\Exception;

use IA\Auth\User\UserInterface;
use Throwable;

abstract class AccountStatusException extends AuthException
{
    /**
     * AccountStatusException constructor.
     * @param UserInterface $user
     * @param string $message
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(
        protected UserInterface $user,
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return UserInterface
     */
    public function getUser(): UserInterface
    {
        return $this->user;
    }

    /**
     * @param UserInterface $user
     */
    public function setUser(UserInterface $user)
    {
        $this->user = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [$this->user, parent::__serialize()];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
        [$this->user, $parentData] = $data;

        parent::__unserialize($parentData);
    }
}