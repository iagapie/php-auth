<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Exception\AuthException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

abstract class AbstractLoginFormAuth extends AbstractAuth implements InteractiveAuthInterface
{
    public const ATTR_ERROR = '__AUTH_LAST_ERROR__';

    /**
     * @param SessionInterface $session
     * @param ResponseFactoryInterface $responseFactory
     * @param LoggerInterface $logger
     */
    public function __construct(
        protected SessionInterface $session,
        protected ResponseFactoryInterface $responseFactory,
        protected LoggerInterface $logger
    ) {
    }

    /**
     * @param string $path
     * @return bool
     */
    abstract protected function checkUriPath(string $path): bool;

    /**
     * @param ServerRequestInterface $request
     * @return string
     */
    abstract protected function getFailurePath(ServerRequestInterface $request): string;

    /**
     * {@inheritDoc}
     */
    public function supports(ServerRequestInterface $request): bool
    {
        return 'POST' === $request->getMethod()
            && $this->checkUriPath(\rawurldecode($request->getUri()->getPath() ?: ''));
    }

    /**
     * {@inheritDoc}
     */
    public function onFailure(ServerRequestInterface $request, AuthException $exception): ServerRequestInterface
    {
        $this->session->set(static::ATTR_ERROR, $exception);

        return $request->withAttribute(static::ATTR_RESPONSE, $this->redirectResponse($this->getFailurePath($request)));
    }

    /**
     * {@inheritDoc}
     */
    public function isInteractive(): bool
    {
        return true;
    }

    /**
     * @param string $url
     * @return ResponseInterface
     */
    protected function redirectResponse(string $url): ResponseInterface
    {
        return $this->responseFactory->createResponse(302)->withHeader('Location', $url);
    }
}