<?php

declare(strict_types=1);

namespace IA\Auth\Event;

use IA\Auth\AuthInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\EventDispatcher\Event;

abstract class AuthEvent extends Event
{
    /**
     * @param ServerRequestInterface $request
     */
    public function __construct(protected ServerRequestInterface $request)
    {
    }

    /**
     * @return ServerRequestInterface
     */
    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    /**
     * @param ServerRequestInterface $request
     */
    public function setRequest(ServerRequestInterface $request): void
    {
        $this->request = $request;
    }

    /**
     * @return ResponseInterface|null
     */
    public function getResponse(): ?ResponseInterface
    {
        return $this->request->getAttribute(AuthInterface::ATTR_RESPONSE);
    }

    /**
     * @param ResponseInterface|null $response
     */
    public function setResponse(?ResponseInterface $response): void
    {
        $this->request = null === $response
            ? $this->request->withoutAttribute(AuthInterface::ATTR_RESPONSE)
            : $this->request->withAttribute(AuthInterface::ATTR_RESPONSE, $response);
    }
}