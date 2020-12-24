<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Exception\BadCredentialsException;
use IA\Auth\Token\Storage\TokenStorageInterface;
use IA\Auth\User\UserProviderInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

use function array_key_exists;
use function sprintf;

class RemoteUserAuth extends AbstractPreAuthenticatedAuth
{
    /**
     * @param SessionInterface $session
     * @param UserProviderInterface $userProvider
     * @param TokenStorageInterface $tokenStorage
     * @param LoggerInterface $logger
     * @param string $firewallName
     * @param string $userLoadMethod
     * @param string $userKey
     */
    public function __construct(
        protected SessionInterface $session,
        UserProviderInterface $userProvider,
        TokenStorageInterface $tokenStorage,
        LoggerInterface $logger,
        string $firewallName,
        string $userLoadMethod = 'loadByUsername',
        protected string $userKey = 'REMOTE_USER'
    ) {
        parent::__construct($userProvider, $tokenStorage, $logger, $firewallName, $userLoadMethod);
    }

    /**
     * {@inheritDoc}
     */
    protected function extractUsername(ServerRequestInterface $request): ?string
    {
        if ($username = $this->session->get(AuthManagerInterface::ATTR_AUTH_USERNAME.$this->firewallName)) {
            return $username;
        }

        if ($username = $request->getAttribute($this->userKey)) {
            return $username;
        }

        if (!array_key_exists($this->userKey, $request->getServerParams())) {
            throw new BadCredentialsException(sprintf('User key was not found: "%s".', $this->userKey));
        }

        return $request->getServerParams()[$this->userKey];
    }
}