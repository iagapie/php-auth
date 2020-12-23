<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\LoginSuccessEvent;
use IA\Auth\Session\SessionStrategyInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class SessionStrategyListener implements EventSubscriberInterface
{
    /**
     * @param SessionStrategyInterface $sessionStrategy
     */
    public function __construct(protected SessionStrategyInterface $sessionStrategy)
    {
    }

    /**
     * @param LoginSuccessEvent $event
     */
    public function onSuccessfulLogin(LoginSuccessEvent $event): void
    {
        $request = $this->sessionStrategy->onAuthentication($event->getRequest(), $event->getAuthToken());

        $event->setRequest($request);
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [LoginSuccessEvent::class => 'onSuccessfulLogin'];
    }
}