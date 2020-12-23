<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\LogoutEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Csrf\TokenStorage\ClearableTokenStorageInterface;

class CsrfTokenClearingLogoutListener implements EventSubscriberInterface
{
    /**
     * @param ClearableTokenStorageInterface $csrfTokenStorage
     */
    public function __construct(protected ClearableTokenStorageInterface $csrfTokenStorage)
    {
    }

    /**
     * @param LogoutEvent $event
     */
    public function onLogout(LogoutEvent $event): void
    {
        $this->csrfTokenStorage->clear();
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [
            LogoutEvent::class => 'onLogout',
        ];
    }
}