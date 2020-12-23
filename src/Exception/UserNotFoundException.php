<?php

declare(strict_types=1);

namespace IA\Auth\Exception;

use Throwable;

class UserNotFoundException extends AuthException
{
    /**
     * @param string $identifier
     * @param string $message
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(
        private string $identifier,
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * @return string
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @param string $identifier
     */
    public function setIdentifier(string $identifier): void
    {
        $this->identifier = $identifier;
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [$this->identifier, parent::__serialize()];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
        [$this->identifier, $parentData] = $data;
        parent::__unserialize($parentData);
    }
}