<?php

declare(strict_types=1);

namespace IA\Auth\User;

use IA\Auth\Exception\UserNotFoundException;
use Doctrine\DBAL\Connection;
use PDO;

use function array_keys;
use function array_map;
use function implode;
use function reset;
use function sprintf;

/**
 *      CREATE TABLE `users` (
 *         `id` INT AUTO_INCREMENT NOT NULL,
 *         `username` VARCHAR(255) NOT NULL,
 *         `email` VARCHAR(255) NOT NULL,
 *         `password` LONGTEXT NOT NULL,
 *         `roles` JSON NOT NULL,
 *         `enabled` TINYINT(1) NOT NULL DEFAULT \'1\',
 *         `account_locked` TINYINT(1) NOT NULL DEFAULT \'0\',
 *         `account_expired` TINYINT(1) NOT NULL DEFAULT \'0\',
 *         `credentials_expired` TINYINT(1) NOT NULL DEFAULT \'0\',
 *         `extra_fields` JSON NOT NULL,
 *         UNIQUE username (`username`),
 *         UNIQUE email (`email`),
 *         PRIMARY KEY(`id`)
 *      ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB;
 */
class DbalUserProvider implements UserProviderInterface
{
    public const TABLE_NAME = 'users';

    /**
     * DbalUserProvider constructor.
     * @param Connection $connection
     */
    public function __construct(protected Connection $connection)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function load(string $value): UserInterface
    {
        return $this->find(
            ['username' => $value, 'email' => $value],
            ['username' => PDO::PARAM_STR, 'email' => PDO::PARAM_STR]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function loadByUsername(string $username): UserInterface
    {
        $column = 'username';

        return $this->find([$column => $username], [$column => PDO::PARAM_STR]);
    }

    /**
     * {@inheritdoc}
     */
    public function loadByEmail(string $email): UserInterface
    {
        $column = 'email';

        return $this->find([$column => $email], [$column => PDO::PARAM_STR]);
    }

    /**
     * {@inheritdoc}
     */
    public function refresh(UserInterface $user): UserInterface
    {
        return $this->loadByUsername($user->getUsername());
    }

    /**
     * @param array<string, string> $values
     * @param array<string, int> $types
     * @return UserInterface
     * @throws UserNotFoundException
     */
    protected function find(array $values, array $types): UserInterface
    {
        $where = array_map(fn ($column) => $column.' = :'.$column, array_keys($values));
        $where = implode(' OR ', $where);

        $sql = "
            SELECT
                *
            FROM
                ".static::TABLE_NAME."
            WHERE
                {$where}
        ";

        if ($row = $this->connection->fetchAssociative($sql, $values, $types)) {
            return $this->toUser($row);
        }

        $value = reset($values);

        throw new UserNotFoundException($value, sprintf('User "%s" not found.', $value));
    }

    /**
     * @param array $row
     * @return UserInterface
     */
    protected function toUser(array $row): UserInterface
    {
        return new User(
            $row['username'],
            $row['email'],
            $row['password'],
            (array)$row['roles'],
            (bool)$row['enabled'],
            !(bool)$row['account_expired'],
            !(bool)$row['credentials_expired'],
            !(bool)$row['account_locked'],
            (array)$row['extra_fields']
        );
    }
}