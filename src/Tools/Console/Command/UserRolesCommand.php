<?php

declare(strict_types=1);

namespace IA\Auth\Tools\Console\Command;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception;
use Doctrine\DBAL\Types\Types;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

class UserRolesCommand extends Command
{
    protected static $defaultName = 'user:roles';

    /**
     * @param Connection $connection
     * @param string $tableName
     * @param string|null $name
     */
    public function __construct(
        protected Connection $connection,
        protected string $tableName = 'users',
        ?string $name = null
    ) {
        parent::__construct($name);
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Change User Roles.')
            ->addArgument(
                'username',
                InputArgument::REQUIRED
            )
            ->addArgument(
                'role',
                InputArgument::OPTIONAL | InputArgument::IS_ARRAY
            );
    }

    /**
     * @param InputInterface $input
     * @param OutputInterface $output
     * @return int
     * @throws Exception
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $username = (string)$input->getArgument('username');
        $roles = (array)$input->getArgument('role');

        $data = ['roles' => $roles];
        $criteria = ['username' => $username];
        $types = ['roles' => Types::JSON];

        $this->connection->update($this->tableName, $data, $criteria, $types);

        if (!$this->connection->isAutoCommit()) {
            $this->connection->commit();
        }

        $io = new SymfonyStyle($input, $output);
        $io->text(
            [
                sprintf('User "<info>%s</info>" was modified successfully.', $username),
                sprintf('Roles: <info>%s</info>', implode(', ', $roles)),
                '',
            ]
        );

        return self::SUCCESS;
    }
}