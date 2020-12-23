<?php

declare(strict_types=1);

namespace IA\Auth;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

trait TargetPathTrait
{
    /**
     * Sets the target path the user should be redirected to after authentication.
     *
     * Usually, you do not need to set this directly.
     * @param SessionInterface $session
     * @param string $firewallName
     * @param string $uri
     */
    private function saveTargetPath(SessionInterface $session, string $firewallName, string $uri): void
    {
        $session->set('__auth_'.$firewallName.'_target_path__', $uri);
    }

    /**
     * Returns the URL (if any) the user visited that forced them to login.
     *
     * @param SessionInterface $session
     * @param string $firewallName
     * @return string|null
     */
    private function getTargetPath(SessionInterface $session, string $firewallName): ?string
    {
        return $session->get('__auth_'.$firewallName.'_target_path__');
    }

    /**
     * Removes the target path from the session.
     * @param SessionInterface $session
     * @param string $firewallName
     */
    private function removeTargetPath(SessionInterface $session, string $firewallName): void
    {
        $session->remove('__auth_'.$firewallName.'_target_path__');
    }
}