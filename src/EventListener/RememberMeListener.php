<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\LoginFailureEvent;
use IA\Auth\Event\LoginSuccessEvent;
use IA\Auth\Passport\Badge\RememberMeBadge;
use IA\Auth\RememberMe\RememberMeServicesInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class RememberMeListener implements EventSubscriberInterface
{
    /**
     * @param RememberMeServicesInterface $rememberMeServices
     * @param LoggerInterface $logger
     */
    public function __construct(
        protected RememberMeServicesInterface $rememberMeServices,
        protected LoggerInterface $logger
    ) {
    }

    /**
     * @param LoginSuccessEvent $event
     */
    public function onSuccessfulLogin(LoginSuccessEvent $event): void
    {
        $passport = $event->getPassport();

        if (!$passport->hasBadge(RememberMeBadge::class)) {
            $this->logger->debug(
                'Remember me skipped: your authenticator does not support it.',
                ['authenticator' => $event->getAuth()::class]
            );

            return;
        }

        if (null === $event->getResponse()) {
            $this->logger->debug(
                'Remember me skipped: the authenticator did not set a success response.',
                ['authenticator' => $event->getAuth()::class]
            );

            return;
        }

        $request = $this->rememberMeServices->loginSuccess($event->getRequest(), $event->getAuthToken());

        $event->setRequest($request);
    }

    /**
     * @param LoginFailureEvent $event
     */
    public function onFailedLogin(LoginFailureEvent $event): void
    {
        $request = $this->rememberMeServices->loginFail($event->getRequest(), $event->getException());

        $event->setRequest($request);
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onSuccessfulLogin',
            LoginFailureEvent::class => 'onFailedLogin',
        ];
    }
}