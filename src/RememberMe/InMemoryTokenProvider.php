<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use IA\Auth\Exception\TokenNotFoundException;
use DateTimeInterface;

class InMemoryTokenProvider implements TokenProviderInterface
{
    /**
     * @var PersistentTokenInterface[]
     */
    private array $tokens = [];

    /**
     * {@inheritDoc}
     */
    public function loadTokenBySeries(string $series): PersistentTokenInterface
    {
        if (!isset($this->tokens[$series])) {
            throw new TokenNotFoundException('No token found.');
        }

        return $this->tokens[$series];
    }

    /**
     * {@inheritDoc}
     */
    public function deleteTokenBySeries(string $series): void
    {
        unset($this->tokens[$series]);
    }

    /**
     * {@inheritDoc}
     */
    public function updateToken(string $series, string $tokenValue, DateTimeInterface $lastUsed): void
    {
        if (!isset($this->tokens[$series])) {
            throw new TokenNotFoundException('No token found.');
        }

        $token = new PersistentToken(
            $this->tokens[$series]->getClass(),
            $this->tokens[$series]->getUsername(),
            $series,
            $tokenValue,
            $lastUsed
        );

        $this->tokens[$series] = $token;
    }

    /**
     * {@inheritDoc}
     */
    public function createNewToken(PersistentTokenInterface $token): void
    {
        $this->tokens[$token->getSeries()] = $token;
    }
}