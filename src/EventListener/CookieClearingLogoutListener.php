<?php

declare(strict_types=1);

namespace IA\Auth\EventListener;

use IA\Auth\Event\LogoutEvent;
use IA\Cookie\CookieJarInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class CookieClearingLogoutListener implements EventSubscriberInterface
{
    /**
     * @param CookieJarInterface $cookieJar
     * @param array|array[] $cookies
     */
    public function __construct(protected CookieJarInterface $cookieJar, protected array $cookies = [])
    {
    }

    /**
     * @param LogoutEvent $event
     */
    public function onLogout(LogoutEvent $event): void
    {
        foreach ($this->cookies as $cookieData) {
            $cookie = $this->cookieJar->forget(...$cookieData);
            $this->cookieJar->add($cookie);
        }
    }

    /**
     * {@inheritDoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [
            LogoutEvent::class => ['onLogout', -255],
        ];
    }
}