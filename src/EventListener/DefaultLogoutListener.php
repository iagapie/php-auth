<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\LogoutEvent;
use IA\Auth\Token\Storage\TokenStorageInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class DefaultLogoutListener implements EventSubscriberInterface
{
    /**
     * @param ResponseFactoryInterface $responseFactory
     * @param TokenStorageInterface $tokenStorage
     * @param string $targetUrl
     */
    public function __construct(
        protected ResponseFactoryInterface $responseFactory,
        protected TokenStorageInterface $tokenStorage,
        protected string $targetUrl = '/'
    ) {
    }

    /**
     * @param LogoutEvent $event
     */
    public function onLogout(LogoutEvent $event): void
    {
        $this->tokenStorage->setToken();

        if (null !== $event->getResponse()) {
            return;
        }

        $event->setResponse($this->responseFactory->createResponse(302)->withHeader('Location', $this->targetUrl));
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [
            LogoutEvent::class => ['onLogout', 64],
        ];
    }
}