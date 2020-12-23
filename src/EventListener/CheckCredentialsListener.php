<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Encoder\UserPasswordEncoderInterface;
use IA\Auth\Event\CheckPassportEvent;
use IA\Auth\Exception\BadCredentialsException;
use IA\Auth\Passport\Credentials\CustomCredentials;
use IA\Auth\Passport\Credentials\PasswordCredentials;
use IA\Auth\Passport\UserPassportInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class CheckCredentialsListener implements EventSubscriberInterface
{
    /**
     * @param UserPasswordEncoderInterface $encoder
     */
    public function __construct(protected UserPasswordEncoderInterface $encoder)
    {
    }

    /**
     * @param CheckPassportEvent $event
     */
    public function checkPassport(CheckPassportEvent $event): void
    {
        $passport = $event->getPassport();

        if ($passport instanceof UserPassportInterface && $passport->hasBadge(PasswordCredentials::class)) {
            // Use the password encoder to validate the credentials
            $user = $passport->getUser();

            /** @var PasswordCredentials $badge */
            $badge = $passport->getBadge(PasswordCredentials::class);

            if ($badge->isResolved()) {
                return;
            }

            $presentedPassword = $badge->getPassword();

            if ('' === $presentedPassword) {
                throw new BadCredentialsException('The presented password cannot be empty.');
            }

            if (null === $user->getPassword()) {
                throw new BadCredentialsException('The presented password is invalid.');
            }

            if (!$this->encoder->isValid($user, $presentedPassword)) {
                throw new BadCredentialsException('The presented password is invalid.');
            }

            $badge->markResolved();

            return;
        }

        if ($passport->hasBadge(CustomCredentials::class)) {
            /** @var CustomCredentials $badge */
            $badge = $passport->getBadge(CustomCredentials::class);
            if ($badge->isResolved()) {
                return;
            }

            $badge->executeCustomChecker($passport->getUser());

            return;
        }
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [CheckPassportEvent::class => 'checkPassport'];
    }
}