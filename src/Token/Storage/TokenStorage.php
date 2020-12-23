<?php

declare(strict_types=1);

namespace IA\Auth\Token\Storage;

use IA\Auth\Token\TokenInterface;
use Symfony\Contracts\Service\ResetInterface;

class TokenStorage implements TokenStorageInterface, ResetInterface
{
    /**
     * @var TokenInterface|null
     */
    protected ?TokenInterface $token = null;

    /**
     * @var callable|null
     */
    protected $initializer;

    /**
     * {@inheritdoc}
     */
    public function getToken(): ?TokenInterface
    {
        if ($initializer = $this->initializer) {
            $this->initializer = null;
            $initializer();
        }

        return $this->token;
    }

    /**
     * {@inheritdoc}
     */
    public function setToken(?TokenInterface $token = null): void
    {
        if ($token) {
            // ensure any initializer is called
            $this->getToken();
        }

        $this->initializer = null;
        $this->token = $token;
    }

    public function reset(): void
    {
        $this->setToken();
    }

    /**
     * @param callable|null $initializer
     */
    public function setInitializer(?callable $initializer): void
    {
        $this->initializer = $initializer;
    }
}