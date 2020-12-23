<?php

declare(strict_types=1);

namespace IA\Auth;

use IA\Auth\Passport\PassportInterface;
use IA\Auth\Passport\UserPassportInterface;
use IA\Auth\Token\PostAuthenticationToken;
use IA\Auth\Token\TokenInterface;
use LogicException;

use function sprintf;

abstract class AbstractAuth implements AuthInterface
{
    /**
     * Shortcut to create a PostAuthenticationToken for you, if you don't really
     * care about which authenticated token you're using.
     *
     * @param PassportInterface $passport
     * @param string $firewallName
     * @return PostAuthenticationToken
     */
    public function createToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        if (!$passport instanceof UserPassportInterface) {
            throw new LogicException(
                sprintf(
                    'Passport does not contain a user, overwrite "createAuthenticatedToken()" in "%s" to create a custom authenticated token.',
                    $this::class
                )
            );
        }

        return new PostAuthenticationToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
    }
}