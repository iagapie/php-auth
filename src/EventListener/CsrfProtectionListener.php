<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\CheckPassportEvent;
use IA\Auth\Exception\InvalidCsrfTokenException;
use IA\Auth\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class CsrfProtectionListener implements EventSubscriberInterface
{
    /**
     * @param CsrfTokenManagerInterface $csrfTokenManager
     */
    public function __construct(protected CsrfTokenManagerInterface $csrfTokenManager)
    {
    }

    /**
     * @param CheckPassportEvent $event
     */
    public function checkPassport(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();

        if (!$passport->hasBadge(CsrfTokenBadge::class)) {
            return;
        }

        /** @var CsrfTokenBadge $badge */
        $badge = $passport->getBadge(CsrfTokenBadge::class);

        if ($badge->isResolved()) {
            return;
        }

        $csrfToken = new CsrfToken($badge->getCsrfTokenId(), $badge->getCsrfToken());

        if (false === $this->csrfTokenManager->isTokenValid($csrfToken)) {
            throw new InvalidCsrfTokenException('Invalid CSRF token.');
        }

        $badge->markResolved();
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [CheckPassportEvent::class => ['checkPassport', 512]];
    }
}