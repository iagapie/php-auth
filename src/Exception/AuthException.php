<?php

declare(strict_types=1);

namespace IA\Auth\Exception;

class AuthException extends \RuntimeException
{
    /**
     * @return array
     */
    public function __serialize(): array
    {
        return [$this->code, $this->message, $this->file, $this->line];
    }

    /**
     * @param array $data
     */
    public function __unserialize(array $data): void
    {
        [$this->code, $this->message, $this->file, $this->line] = $data;
    }

    /**
     * @internal
     */
    public function __sleep(): array
    {
        $this->serialized = $this->__serialize();

        return ['serialized'];
    }

    /**
     * @internal
     */
    public function __wakeup(): void
    {
        $this->__unserialize($this->serialized);
        unset($this->serialized);
    }
}