<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Event\AuthenticationSuccessEvent;
use IA\Auth\Event\AuthenticationTokenCreatedEvent;
use IA\Auth\Event\CheckPassportEvent;
use IA\Auth\Event\InteractiveLoginEvent;
use IA\Auth\Event\LoginFailureEvent;
use IA\Auth\Event\LoginSuccessEvent;
use IA\Auth\Event\LogoutEvent;
use IA\Auth\Exception\AuthException;
use IA\Auth\Passport\Badge\UserBadge;
use IA\Auth\Passport\PassportInterface;
use IA\Auth\Passport\SelfValidatingPassport;
use IA\Auth\Token\Storage\TokenStorageInterface;
use IA\Auth\Token\TokenInterface;
use IA\Auth\User\UserInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class AuthManager implements AuthManagerInterface
{
    /**
     * @param AuthInterface[] $auths
     * @param TokenStorageInterface $tokenStorage
     * @param EventDispatcherInterface $eventDispatcher
     * @param SessionInterface $session
     * @param LoggerInterface $logger
     * @param string $firewallName
     * @param bool $eraseCredentials
     */
    public function __construct(
        protected array $auths,
        protected TokenStorageInterface $tokenStorage,
        protected EventDispatcherInterface $eventDispatcher,
        protected SessionInterface $session,
        protected LoggerInterface $logger,
        protected string $firewallName,
        protected bool $eraseCredentials = true
    ) {
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request): ServerRequestInterface
    {
        foreach ($this->auths as $auth) {
            if (!$auth->supports($request)) {
                $this->logger->debug(
                    'Skipping the "{authenticator}" authenticator as it did not support the request.',
                    ['authenticator' => $auth::class]
                );

                continue;
            }

            $request = $this->executeAuth($request, $auth);

            if (null !== $request->getAttribute(AuthInterface::ATTR_RESPONSE)) {
                $this->logger->debug(
                    'The "{authenticator}" authenticator set the response. Any later authenticator will not be called',
                    ['authenticator' => $auth::class]
                );

                return $request;
            }

            $this->logger->debug(
                'Authenticator set no success response: request continues.',
                ['authenticator' => $auth::class]
            );
        }

        return $request;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticateUser(
        ServerRequestInterface $request,
        AuthInterface $auth,
        UserInterface $user,
        array $badges = []
    ): ServerRequestInterface {
        // create an authenticated token for the User
        $token = $auth->createToken(
            $passport = new SelfValidatingPassport(new UserBadge($user->getUsername(), fn() => $user), $badges),
            $this->firewallName
        );

        // announce the authenticated token
        $token = $this->eventDispatcher->dispatch(new AuthenticationTokenCreatedEvent($token))->getAuthenticatedToken();

        $request = $request->withAttribute(AuthInterface::ATTR_PASSPORT, $passport);

        // authenticate this in the system
        return $this->handleSuccess($request, $auth, $token);
    }

    /**
     * {@inheritDoc}
     */
    public function logout(ServerRequestInterface $request): ServerRequestInterface
    {
        $this->session->remove(self::ATTR_AUTH_USERNAME);

        return $this->eventDispatcher->dispatch(
            new LogoutEvent($request, $this->tokenStorage->getToken())
        )->getRequest();
    }

    /**
     * @param ServerRequestInterface $request
     * @param AuthInterface $auth
     * @return ServerRequestInterface
     */
    protected function executeAuth(ServerRequestInterface $request, AuthInterface $auth): ServerRequestInterface
    {
        try {
            // get the passport from the Authenticator
            $request = $auth->authenticate($request);

            /** @var PassportInterface $passport */
            $passport = $request->getAttribute(AuthInterface::ATTR_PASSPORT);

            // check the passport (e.g. password checking)
            $this->eventDispatcher->dispatch(new CheckPassportEvent($auth, $passport));

            // check if all badges are resolved
            $passport->checkIfCompletelyResolved();

            // create the authenticated token
            $authToken = $auth->createToken($passport, $this->firewallName);

            // announce the authenticated token
            /** @var TokenInterface $authToken */
            $authToken = $this->eventDispatcher->dispatch(
                new AuthenticationTokenCreatedEvent($authToken)
            )->getAuthToken();

            if (true === $this->eraseCredentials) {
                $authToken->eraseCredentials();
            }

            $this->eventDispatcher->dispatch(new AuthenticationSuccessEvent($authToken));

            $this->logger->info(
                'Authenticator successful!',
                ['token' => $authToken, 'authenticator' => $auth::class]
            );

            // success! (sets the token on the token storage, etc)
            return $this->handleSuccess($request, $auth, $authToken);
        } catch (AuthException $e) {
            // oh no! Authentication failed!
            return $this->handleFailure($request, $auth, $e);
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @param AuthInterface $auth
     * @param TokenInterface $authToken
     * @return ServerRequestInterface
     */
    protected function handleSuccess(
        ServerRequestInterface $request,
        AuthInterface $auth,
        TokenInterface $authToken
    ): ServerRequestInterface {
        $this->tokenStorage->setToken($authToken);

        $this->session->set(self::ATTR_AUTH_USERNAME, $authToken->getUsername());

        $request = $auth->onSuccess($request, $authToken, $this->firewallName);

        if ($auth instanceof InteractiveAuthInterface && $auth->isInteractive()) {
            $request = $this->eventDispatcher->dispatch(new InteractiveLoginEvent($request, $authToken))->getRequest();
        }

        return $this->eventDispatcher->dispatch(
            new LoginSuccessEvent(
                $request,
                $auth,
                $authToken,
                $this->firewallName
            )
        )->getRequest();
    }

    /**
     * @param ServerRequestInterface $request
     * @param AuthInterface $auth
     * @param AuthException $exception
     * @return ServerRequestInterface
     */
    protected function handleFailure(
        ServerRequestInterface $request,
        AuthInterface $auth,
        AuthException $exception
    ): ServerRequestInterface {
        $this->session->remove(self::ATTR_AUTH_USERNAME);

        $this->logger->info(
            'Authenticator failed.',
            ['exception' => $exception, 'authenticator' => $auth::class]
        );

        $request = $auth->onFailure($request, $exception);

        if (null !== $request->getAttribute(AuthInterface::ATTR_RESPONSE)) {
            $this->logger->debug(
                'The "{authenticator}" authenticator set the failure response.',
                ['authenticator' => $auth::class]
            );
        }

        return $this->eventDispatcher->dispatch(
            new LoginFailureEvent(
                $request,
                $auth,
                $exception,
                $this->firewallName
            )
        )->getRequest();
    }
}