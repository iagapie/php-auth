<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Exception\BadCredentialsException;
use IA\Auth\Passport\Badge\CsrfTokenBadge;
use IA\Auth\Passport\Badge\RememberMeBadge;
use IA\Auth\Passport\Badge\UserBadge;
use IA\Auth\Passport\Credentials\PasswordCredentials;
use IA\Auth\Passport\Passport;
use IA\Auth\Passport\PassportInterface;
use IA\Auth\Token\TokenInterface;
use IA\Auth\Token\UsernamePasswordToken;
use IA\Auth\User\UserProviderInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

use function gettype;
use function is_object;
use function is_string;
use function method_exists;
use function sprintf;
use function strlen;
use function strpos;
use function substr;
use function trim;

class FormLoginAuth extends AbstractLoginFormAuth
{
    public const ATTR_LAST_USERNAME = '__AUTH_LAST_USERNAME__';

    protected const MAX_USERNAME_LENGTH = 4096;

    use TargetPathTrait;

    /**
     * @param UserProviderInterface $userProvider
     * @param SessionInterface $session
     * @param ResponseFactoryInterface $responseFactory
     * @param LoggerInterface $logger
     * @param array $options
     * @param string $userLoadMethod
     */
    public function __construct(
        protected UserProviderInterface $userProvider,
        SessionInterface $session,
        ResponseFactoryInterface $responseFactory,
        LoggerInterface $logger,
        protected array $options = [],
        protected string $userLoadMethod = 'load'
    ) {
        parent::__construct($session, $responseFactory, $logger);

        $default = [
            'username_parameter' => '_username',
            'password_parameter' => '_password',
            'login_path' => '/login',
            'check_path' => '/login_check',
            'failure_path_parameter' => '_failure_path',
            'failure_path' => null,
            'enable_csrf' => false,
            'csrf_parameter' => '_csrf_token',
            'csrf_token_id' => 'authenticate',
            'always_use_default_target_path' => false,
            'default_target_path' => '/',
            'target_path_parameter' => '_target_path',
            'use_referer' => false,
        ];

        $this->options += $default;
    }

    /**
     * {@inheritDoc}
     */
    public function createToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        return new UsernamePasswordToken($passport->getUser(), null, $firewallName, $passport->getUser()->getRoles());
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(ServerRequestInterface $request): ServerRequestInterface
    {
        $credentials = $this->getCredentials($request);

        $passport = new Passport(
            new UserBadge(
                $credentials['username'],
                fn (string $username) => $this->userProvider->{$this->userLoadMethod}($username)
            ), new PasswordCredentials($credentials['password']), [new RememberMeBadge()]
        );

        if ($this->options['enable_csrf']) {
            $passport->addBadge(new CsrfTokenBadge($this->options['csrf_token_id'], $credentials['csrf_token']));
        }

        return $request->withAttribute(static::ATTR_PASSPORT, $passport);
    }

    /**
     * {@inheritDoc}
     */
    public function onSuccess(
        ServerRequestInterface $request,
        TokenInterface $token,
        string $firewallName
    ): ServerRequestInterface {
        return $request->withAttribute(
            static::ATTR_RESPONSE,
            $this->redirectResponse($this->determineTargetUrl($request, $firewallName))
        );
    }

    /**
     * {@inheritDoc}
     */
    protected function checkUriPath(string $path): bool
    {
        return $path === $this->options['check_path'];
    }

    /**
     * {@inheritDoc}
     */
    protected function getFailurePath(ServerRequestInterface $request): string
    {
        if ($failureUrl = $request->getParsedBody()[$this->options['failure_path_parameter']] ?? null) {
            $this->options['failure_path'] = $failureUrl;
        }

        if (null === $this->options['failure_path']) {
            $this->options['failure_path'] = $this->options['login_path'];
        }

        $this->logger->debug(
            'Authentication failure, redirect triggered.',
            ['failure_path' => $this->options['failure_path']]
        );

        return $this->options['failure_path'];
    }

    /**
     * @param ServerRequestInterface $request
     * @return array<string, string>
     * @throws BadRequestException
     * @throws BadCredentialsException
     */
    protected function getCredentials(ServerRequestInterface $request): array
    {
        $body = (array)$request->getParsedBody();

        $credentials = [
            'csrf_token' => $body[$this->options['csrf_parameter']] ?? null,
            'username' => $body[$this->options['username_parameter']] ?? null,
            'password' => $body[$this->options['password_parameter']] ?? '',
        ];

        if (!is_string($credentials['username'])
            && (!is_object($credentials['username'])
                || !method_exists($credentials['username'], '__toString'))) {
            throw new BadRequestException(
                sprintf(
                    'The key "%s" must be a string, "%s" given.',
                    $this->options['username_parameter'],
                    gettype($credentials['username'])
                )
            );
        }

        $credentials['username'] = trim($credentials['username']);

        if (strlen($credentials['username']) > self::MAX_USERNAME_LENGTH) {
            throw new BadCredentialsException('Invalid username.');
        }

        $this->session->set(static::ATTR_LAST_USERNAME, $credentials['username']);

        return $credentials;
    }

    /**
     * Builds the target URL according to the defined options.
     *
     * @param ServerRequestInterface $request
     * @param string $firewallName
     * @return string
     */
    protected function determineTargetUrl(ServerRequestInterface $request, string $firewallName): string
    {
        if ($this->options['always_use_default_target_path']) {
            return $this->options['default_target_path'];
        }

        if ($targetUrl = $request->getParsedBody()[$this->options['target_path_parameter']] ?? null) {
            return $targetUrl;
        }

        if ($targetUrl = $this->getTargetPath($this->session, $firewallName)) {
            $this->removeTargetPath($this->session, $firewallName);

            return $targetUrl;
        }

        if ($this->options['use_referer'] && $targetUrl = $request->getHeader('Referer')[0] ?? null) {
            if (false !== $pos = strpos($targetUrl, '?')) {
                $targetUrl = substr($targetUrl, 0, $pos);
            }

            if ($targetUrl && $targetUrl !== $this->options['login_path']) {
                return $targetUrl;
            }
        }

        return $this->options['default_target_path'];
    }
}