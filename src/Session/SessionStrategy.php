<?php

declare(strict_types=1);

namespace IA\Auth\Session;

use IA\Auth\Token\TokenInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

final class SessionStrategy implements SessionStrategyInterface
{
    public const NONE = 'none';
    public const MIGRATE = 'migrate';
    public const INVALIDATE = 'invalidate';

    /**
     * SessionStrategy constructor.
     * @param SessionInterface $session
     * @param string $strategy
     */
    public function __construct(private SessionInterface $session, private string $strategy = self::MIGRATE)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function onAuthentication(ServerRequestInterface $request, TokenInterface $token): ServerRequestInterface
    {
        switch ($this->strategy) {
            case self::NONE:
                return $request;

            case self::MIGRATE:
                $this->session->migrate(true);

                return $request;

            case self::INVALIDATE:
                $this->session->invalidate();

                return $request;

            default:
                throw new \RuntimeException(sprintf('Invalid session authentication strategy "%s".', $this->strategy));
        }
    }
}