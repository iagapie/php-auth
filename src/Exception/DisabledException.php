<?php

declare(strict_types=1);

namespace IA\Auth\Exception;

use IA\Auth\User\UserInterface;
use Throwable;

class DisabledException extends AccountStatusException
{
    /**
     * @param UserInterface $user
     * @param string $message
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(
        UserInterface $user,
        string $message = 'Account is disabled.',
        int $code = 0,
        ?Throwable $previous = null
    ) {
        parent::__construct($user, $message, $code, $previous);
    }
}