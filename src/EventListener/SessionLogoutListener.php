<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\LogoutEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class SessionLogoutListener implements EventSubscriberInterface
{
    /**
     * @param SessionInterface $session
     */
    public function __construct(protected SessionInterface $session)
    {
    }

    /**
     * @param LogoutEvent $event
     */
    public function onLogout(LogoutEvent $event): void
    {
        $this->session->invalidate();
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