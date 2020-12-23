<?php

declare(strict_types=1);

namespace IA\Auth\RememberMe;

use IA\Auth\Exception\TokenNotFoundException;
use DateTimeImmutable;
use DateTimeInterface;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Types\Types;
use PDO;

/**
 * This class provides storage for the tokens that is set in "remember me"
 * cookies. This way no password secrets will be stored in the cookies on
 * the client machine, and thus the security is improved.
 *
 * This depends only on doctrine in order to get a database connection
 * and to do the conversion of the datetime column.
 *
 * In order to use this class, you need the following table in your database:
 *
 *     CREATE TABLE `remember_me_token` (
 *         `id`        INT          AUTO_INCREMENT NOT NULL,
 *         `series`    CHAR(88)     NOT NULL,
 *         `value`     CHAR(88)     NOT NULL,
 *         `last_used` DATETIME     NOT NULL,
 *         `class`     VARCHAR(100) NOT NULL,
 *         `username`  VARCHAR(200) NOT NULL,
 *         UNIQUE series (`series`),
 *         PRIMARY KEY(`id`)
 *     ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB;
 */
class DbalTokenProvider implements TokenProviderInterface
{
    public const TABLE_NAME = 'remember_me_token';

    /**
     * DbalTokenProvider constructor.
     * @param Connection $connection
     */
    public function __construct(private Connection $connection)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function loadTokenBySeries(string $series): PersistentTokenInterface
    {
        $sql = '
            SELECT
                class, username, value, last_used
            FROM
                '.static::TABLE_NAME.'
            WHERE
                series = :series
        ';

        $paramValues = ['series' => $series];
        $paramTypes = ['series' => PDO::PARAM_STR];

        if ($row = $this->connection->fetchAssociative($sql, $paramValues, $paramTypes)) {
            return $this->toPersistentToken($row, $series);
        }

        throw new TokenNotFoundException('No token found.');
    }

    /**
     * {@inheritdoc}
     */
    public function deleteTokenBySeries(string $series): void
    {
        $this->connection->delete(static::TABLE_NAME, ['series' => $series], ['series' => PDO::PARAM_STR]);

        if (!$this->connection->isAutoCommit()) {
            $this->connection->commit();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function updateToken(string $series, string $tokenValue, DateTimeInterface $lastUsed): void
    {
        $paramValues = [
            'value' => $tokenValue,
            'last_used' => $lastUsed,
        ];

        $paramTypes = [
            'value' => PDO::PARAM_STR,
            'last_used' => Types::DATETIME_MUTABLE,
        ];

        if ($this->connection->update(static::TABLE_NAME, $paramValues, ['series' => $series], $paramTypes) < 1) {
            throw new TokenNotFoundException('No token found.');
        }

        if (!$this->connection->isAutoCommit()) {
            $this->connection->commit();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function createNewToken(PersistentTokenInterface $token): void
    {
        $paramValues = [
            'class' => $token->getClass(),
            'username' => $token->getUsername(),
            'series' => $token->getSeries(),
            'value' => $token->getTokenValue(),
            'last_used' => $token->getLastUsed(),
        ];

        $paramTypes = [
            'class' => PDO::PARAM_STR,
            'username' => PDO::PARAM_STR,
            'series' => PDO::PARAM_STR,
            'value' => PDO::PARAM_STR,
            'last_used' => Types::DATETIME_MUTABLE,
        ];

        $this->connection->insert(static::TABLE_NAME, $paramValues, $paramTypes);

        if (!$this->connection->isAutoCommit()) {
            $this->connection->commit();
        }
    }

    /**
     * @param array $row
     * @param string $series
     * @return PersistentTokenInterface
     * @throws \Exception
     */
    protected function toPersistentToken(array $row, string $series): PersistentTokenInterface
    {
        return new PersistentToken(
            $row['class'],
            $row['username'],
            $series,
            $row['value'],
            new DateTimeImmutable($row['last_used'])
        );
    }
}