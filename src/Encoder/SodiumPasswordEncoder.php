<?php

declare(strict_types=1);

namespace IA\Auth\Encoder;

use IA\Auth\Exception\BadCredentialsException;

use InvalidArgumentException;
use SodiumException;

use function max;
use function sodium_crypto_pwhash_str;
use function sodium_crypto_pwhash_str_needs_rehash;
use function sodium_crypto_pwhash_str_verify;
use function strlen;

use const SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;

class SodiumPasswordEncoder implements PasswordEncoderInterface
{
    protected const MAX_PASSWORD_LENGTH = 4096;

    protected int $opsLimit;
    protected int $memLimit;

    /**
     * SodiumPasswordEncoder constructor.
     * @param int|null $opsLimit
     * @param int|null $memLimit
     */
    public function __construct(?int $opsLimit = null, ?int $memLimit = null)
    {
        $this->opsLimit = $opsLimit ?? max(4, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE);
        $this->memLimit = $memLimit ?? max(64 * 1024 * 1024, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);

        if (3 > $this->opsLimit) {
            throw new InvalidArgumentException('$opsLimit must be 3 or greater.');
        }

        if (10 * 1024 > $this->memLimit) {
            throw new InvalidArgumentException('$memLimit must be 10k or greater.');
        }
    }

    /**
     * {@inheritdoc}
     *
     * @throws SodiumException
     */
    public function encode(string $raw, ?string $salt = null): string
    {
        if (strlen($raw) > self::MAX_PASSWORD_LENGTH) {
            throw new BadCredentialsException('Invalid password.');
        }

        return sodium_crypto_pwhash_str($raw, $this->opsLimit, $this->memLimit);
    }

    /**
     * {@inheritdoc}
     *
     * @throws SodiumException
     */
    public function isValid(string $encoded, string $raw, ?string $salt = null): bool
    {
        if ('' === $raw || '' === $encoded || strlen($raw) > self::MAX_PASSWORD_LENGTH) {
            return false;
        }

        return sodium_crypto_pwhash_str_verify($encoded, $raw);
    }

    /**
     * {@inheritdoc}
     */
    public function needsRehash(string $encoded): bool
    {
        return sodium_crypto_pwhash_str_needs_rehash($encoded, $this->opsLimit, $this->memLimit);
    }
}