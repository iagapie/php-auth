<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use Exception;
use IA\Auth\AuthManagerInterface;
use IA\Auth\Exception\AuthException;
use IA\Auth\Exception\CookieTheftException;
use IA\Auth\Exception\UnsupportedUserException;
use IA\Auth\Exception\UserNotFoundException;
use IA\Auth\Token\RememberMeToken;
use IA\Auth\Token\TokenInterface;
use IA\Auth\User\UserInterface;
use IA\Auth\User\UserProviderInterface;
use IA\Cookie\CookieJarInterface;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

use function base64_decode;
use function base64_encode;
use function explode;
use function implode;
use function is_string;
use function sprintf;
use function str_contains;

abstract class AbstractRememberMeServices implements RememberMeServicesInterface
{
    protected const COOKIE_DELIMITER = ':';

    /**
     * @param UserProviderInterface $userProvider
     * @param SessionInterface $session
     * @param CookieJarInterface $cookieJar
     * @param LoggerInterface $logger
     * @param string $secret
     * @param string $firewallName
     * @param array $options
     */
    public function __construct(
        protected UserProviderInterface $userProvider,
        protected SessionInterface $session,
        protected CookieJarInterface $cookieJar,
        protected LoggerInterface $logger,
        protected string $secret,
        protected string $firewallName,
        protected array $options = []
    ) {
        if (empty($secret)) {
            throw new InvalidArgumentException('$secret must not be empty.');
        }

        if (empty($firewallName)) {
            throw new InvalidArgumentException('$firewallName must not be empty.');
        }

        $this->options += [
            'name' => 'REMEMBERME',
            'expire' => 31536000,
            'path' => '/',
            'domain' => null,
            'secure' => null,
            'http_only' => true,
            'same_site' => null,
            'always_remember_me' => false,
            'remember_me_parameter' => '_remember_me',
        ];
    }

    /**
     * Subclasses should validate the cookie and do any additional processing
     * that is required. This is called from autoLogin().
     *
     * @param ServerRequestInterface $request
     * @param array $cookieParts
     * @return UserInterface
     */
    abstract protected function processAutoLoginCookie(
        ServerRequestInterface $request,
        array $cookieParts
    ): UserInterface;

    /**
     * This is called after a user has been logged in successfully, and has
     * requested remember-me capabilities. The implementation usually sets a
     * cookie and possibly stores a persistent record of it.
     *
     * @param ServerRequestInterface $request
     * @param TokenInterface $token
     * @return ServerRequestInterface
     */
    abstract protected function onLoginSuccess(ServerRequestInterface $request, TokenInterface $token): ServerRequestInterface;

    /**
     * @param ServerRequestInterface $request
     * @param Exception|null $exception
     * @return ServerRequestInterface
     */
    protected function onLoginFail(ServerRequestInterface $request, Exception $exception = null): ServerRequestInterface
    {
        return $request;
    }

    /**
     * {@inheritDoc}
     */
    final public function logout(ServerRequestInterface $request): ServerRequestInterface
    {
        return $this->cancelCookie($request);
    }

    /**
     * {@inheritDoc}
     */
    final public function autoLogin(ServerRequestInterface $request): ServerRequestInterface
    {
        if (($cookie = $this->cookieJar->get($this->options['name'], $this->options['path']))
            && null === $cookie->getValue()) {
            return $request;
        }

        if (null === $cookie = ($request->getCookieParams()[$this->options['name']] ?? null)) {
            return $request;
        }

        $this->logger->debug('Remember-me cookie detected.');

        $cookieParts = $this->decodeCookie($cookie);

        try {
            $user = $this->processAutoLoginCookie($request, $cookieParts);

            $this->logger->info('Remember-me cookie accepted.');

            $token = new RememberMeToken($user, $this->firewallName, $this->secret);

            return $request->withAttribute(self::ATTR_REMEMBER_ME_TOKEN, $token);
        } catch (CookieTheftException $e) {
            $this->loginFail($request, $e);

            throw $e;
        } catch (UserNotFoundException $e) {
            $this->logger->info('User for remember-me cookie not found.', ['exception' => $e]);

            return $this->loginFail($request, $e);
        } catch (UnsupportedUserException $e) {
            $this->logger->warning('User class for remember-me cookie not supported.', ['exception' => $e]);

            return $this->loginFail($request, $e);
        } catch (AuthException $e) {
            $this->logger->debug('Remember-Me authentication failed.', ['exception' => $e]);

            return $this->loginFail($request, $e);
        } catch (Exception $e) {
            $this->loginFail($request, $e);

            throw $e;
        }
    }

    /**
     * {@inheritDoc}
     */
    final public function loginSuccess(ServerRequestInterface $request, TokenInterface $token): ServerRequestInterface
    {
        // Make sure any old remember-me cookies are cancelled
        $request = $this->cancelCookie($request);

        if (!$token->getUser() instanceof UserInterface) {
            $this->logger->debug('Remember-me ignores token since it does not contain a UserInterface implementation.');

            return $request;
        }

        if (!$this->isRememberMeRequested($request)) {
            $this->logger->debug('Remember-me was not requested.');

            return $request;
        }

        $this->logger->debug('Remember-me was requested; setting cookie.');

        // Remove cookie from bag.
        // It was set by $this->cancelCookie()
        // (cancelCookie does other things too for some RememberMeServices
        // so we should still call it at the start of this method)
        $this->cookieJar->remove($this->options['name'], $this->options['path']);

        $this->session->remove(AuthManagerInterface::ATTR_AUTH_USERNAME.$this->firewallName);

        return $this->onLoginSuccess($request, $token);
    }

    /**
     * {@inheritDoc}
     */
    final public function loginFail(ServerRequestInterface $request, Exception $exception = null): ServerRequestInterface
    {
        $request = $this->cancelCookie($request);

        return $this->onLoginFail($request, $exception);
    }

    /**
     * Decodes the raw cookie value.
     *
     * @param string $rawCookie
     * @return array
     */
    protected function decodeCookie(string $rawCookie): array
    {
        return explode(self::COOKIE_DELIMITER, base64_decode($rawCookie));
    }

    /**
     * Encodes the cookie parts.
     *
     * @param array $cookieParts
     * @return string
     */
    protected function encodeCookie(array $cookieParts): string
    {
        foreach ($cookieParts as $cookiePart) {
            if (is_string($cookiePart) && str_contains($cookiePart, self::COOKIE_DELIMITER)) {
                throw new InvalidArgumentException(
                    sprintf('$cookieParts should not contain the cookie delimiter "%s".', self::COOKIE_DELIMITER)
                );
            }
        }

        return base64_encode(implode(self::COOKIE_DELIMITER, $cookieParts));
    }

    /**
     * Deletes the remember-me cookie.
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface
     */
    protected function cancelCookie(ServerRequestInterface $request): ServerRequestInterface
    {
        $this->logger->debug('Clearing remember-me cookie.', ['name' => $this->options['name']]);

        $cookie = $this->cookieJar->forget($this->options['name'], $this->options['path'], $this->options['domain']);

        $this->cookieJar->add($cookie);

        $request = $request->withoutAttribute(self::ATTR_REMEMBER_ME_TOKEN);

        return $request;
    }

    /**
     * Checks whether remember-me capabilities were requested.
     *
     * @param ServerRequestInterface $request
     * @return bool
     */
    protected function isRememberMeRequested(ServerRequestInterface $request): bool
    {
        if (true === $this->options['always_remember_me']) {
            return true;
        }

        $body = (array)$request->getParsedBody();

        $parameter = $body[$this->options['remember_me_parameter']] ?? null;

        if (null === $parameter) {
            $this->logger->debug(
                'Did not send remember-me cookie.',
                ['parameter' => $this->options['remember_me_parameter']]
            );
        }

        return 'true' === $parameter || 'on' === $parameter || '1' === $parameter || 'yes' === $parameter || true === $parameter;
    }
}