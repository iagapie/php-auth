<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Exception\AuthException;
use IA\Auth\Exception\BadCredentialsException;
use IA\Auth\Passport\Badge\UserBadge;
use IA\Auth\Passport\Credentials\PasswordCredentials;
use IA\Auth\Passport\Passport;
use IA\Auth\Passport\PassportInterface;
use IA\Auth\Token\TokenInterface;
use IA\Auth\Token\UsernamePasswordToken;
use IA\Auth\User\UserProviderInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;

use function is_string;
use function json_encode;
use function sprintf;
use function str_contains;
use function strlen;

class JsonLoginAuth implements InteractiveAuthInterface
{
    protected const MAX_USERNAME_LENGTH = 4096;

    /**
     * @param UserProviderInterface $userProvider
     * @param ResponseFactoryInterface $responseFactory
     * @param StreamFactoryInterface $streamFactory
     * @param bool $debug
     * @param array $options
     * @param string $userLoadMethod
     */
    public function __construct(
        protected UserProviderInterface $userProvider,
        protected ResponseFactoryInterface $responseFactory,
        protected StreamFactoryInterface $streamFactory,
        protected bool $debug,
        protected array $options = [],
        protected string $userLoadMethod = 'load'
    ) {
        $default = [
            'username_path' => 'username',
            'password_path' => 'password',
            //'check_path' => '/login_check',
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
    public function supports(ServerRequestInterface $request): bool
    {
        if (!str_contains($request->getHeaderLine('Content-Type'), 'json')) {
            return false;
        }

        if (isset($this->options['check_path'])
            && !str_contains($request->getUri()->getPath(), $this->options['check_path'])) {
            return false;
        }

        return true;
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
                fn(string $username) => $this->userProvider->{$this->userLoadMethod}($username)
            ), new PasswordCredentials($credentials['password'])
        );

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
        return $request; // let the original request continue
    }

    /**
     * {@inheritDoc}
     */
    public function onFailure(ServerRequestInterface $request, AuthException $exception): ServerRequestInterface
    {
        $data = [
            'message' => 'The request requires valid user authentication.',
        ];

        if ($this->debug) {
            $data += [
                'exception' => [
                    'code' => $exception->getCode(),
                    'file' => $exception->getFile(),
                    'line' => $exception->getLine(),
                    'trace' => $exception->getTraceAsString(),
                ],
            ];
        }

        $response = $this->responseFactory
            ->createResponse(401)
            ->withBody($this->streamFactory->createStream(json_encode($data)));

        return $request->withAttribute(static::ATTR_RESPONSE, $response);
    }

    /**
     * {@inheritDoc}
     */
    public function isInteractive(): bool
    {
        return true;
    }

    /**
     * @param ServerRequestInterface $request
     * @return array<string, string>
     */
    protected function getCredentials(ServerRequestInterface $request): array
    {
        $data = $request->getParsedBody();

        $credentials = [];

        $credentials['username'] = $data[$this->options['username_path']] ?? null;

        if (!is_string($credentials['username'])) {
            throw new BadRequestException(
                sprintf('The key "%s" must be a string.', $this->options['username_path'])
            );
        }

        if (strlen($credentials['username']) > static::MAX_USERNAME_LENGTH) {
            throw new BadCredentialsException('Invalid username.');
        }

        $credentials['password'] = $data[$this->options['password_path']] ?? null;

        if (!is_string($credentials['password'])) {
            throw new BadRequestException(
                sprintf('The key "%s" must be a string.', $this->options['password_path'])
            );
        }

        return $credentials;
    }
}