<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\LogoutEvent;
use IA\Auth\RememberMe\RememberMeServicesInterface;
use LogicException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

use function sprintf;

class RememberMeLogoutListener implements EventSubscriberInterface
{
    /**
     * @param RememberMeServicesInterface $rememberMeServices
     */
    public function __construct(protected RememberMeServicesInterface $rememberMeServices)
    {
    }

    /**
     * @param LogoutEvent $event
     */
    public function onLogout(LogoutEvent $event): void
    {
        if (!$event->getAuthToken()) {
            return;
        }

        if (null === $event->getResponse()) {
            throw new LogicException(
                sprintf(
                    'No response was set for this logout action. Make sure the DefaultLogoutListener or another listener has set the response before "%s" is called.',
                    __CLASS__
                )
            );
        }

        $request = $this->rememberMeServices->logout($event->getRequest());

        $event->setRequest($request);
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