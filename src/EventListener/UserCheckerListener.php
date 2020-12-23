<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\CheckPassportEvent;
use IA\Auth\Event\LoginSuccessEvent;
use IA\Auth\Passport\Badge\PreAuthenticatedUserBadge;
use IA\Auth\Passport\UserPassportInterface;
use IA\Auth\User\UserCheckerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class UserCheckerListener implements EventSubscriberInterface
{
    /**
     * @param UserCheckerInterface $userChecker
     */
    public function __construct(protected UserCheckerInterface $userChecker)
    {
    }

    /**
     * @param CheckPassportEvent $event
     */
    public function preCheckCredentials(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();

        if (!$passport instanceof UserPassportInterface || $passport->hasBadge(PreAuthenticatedUserBadge::class)) {
            return;
        }

        $this->userChecker->checkPreAuth($passport->getUser());
    }

    /**
     * @param LoginSuccessEvent $event
     */
    public function postCheckCredentials(LoginSuccessEvent $event): void
    {
        $passport = $event->getPassport();

        if (!$passport instanceof UserPassportInterface || null === $passport->getUser()) {
            return;
        }

        $this->userChecker->checkPostAuth($passport->getUser());
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [
            CheckPassportEvent::class => ['preCheckCredentials', 256],
            LoginSuccessEvent::class => ['postCheckCredentials', 256],
        ];
    }
}