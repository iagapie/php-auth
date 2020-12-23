<?php

declare(strict_types=1);

namespace IA\Auth\Tools\Console\Command;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception;
use Doctrine\DBAL\Types\Types;
use IA\Auth\Encoder\PasswordEncoderInterface;
use PDO;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

class UserCreateCommand extends Command
{
    protected static $defaultName = 'user:create';

    /**
     * @param Connection $connection
     * @param PasswordEncoderInterface $passwordEncoder
     * @param string $tableName
     * @param string|null $name
     */
    public function __construct(
        protected Connection $connection,
        protected PasswordEncoderInterface $passwordEncoder,
        protected string $tableName = 'users',
        ?string $name = null
    ) {
        parent::__construct($name);
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Create User.')
            ->addArgument(
                'username',
                InputArgument::REQUIRED
            )
            ->addArgument(
                'email',
                InputArgument::REQUIRED
            )
            ->addArgument(
                'password',
                InputArgument::REQUIRED
            )
            ->addOption(
                'disabled',
                null,
                InputOption::VALUE_NONE,
            )
            ->addOption(
                'role',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                '',
                ['ROLE_USER']
            )
            ->addOption(
                'account-expired',
                null,
                InputOption::VALUE_NONE,
            )
            ->addOption(
                'credentials-expired',
                null,
                InputOption::VALUE_NONE,
            )
            ->addOption(
                'account-locked',
                null,
                InputOption::VALUE_NONE,
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
        $email = (string)$input->getArgument('email');
        $password = (string)$input->getArgument('password');
        $roles = (array)$input->getOption('role');
        $enabled = !(bool)$input->getOption('disabled');
        $accountNonExpired = !(bool)$input->getOption('account-expired');
        $credentialsNonExpired = !(bool)$input->getOption('credentials-expired');
        $accountNonLocked = !(bool)$input->getOption('account-locked');

        do {
            $password = $this->passwordEncoder->encode($password);
        } while ($this->passwordEncoder->needsRehash($password));

        $data = [
            'username' => $username,
            'email' => $email,
            'password' => $password,
            'roles' => $roles,
            'enabled' => $enabled,
            'account_locked' => !$accountNonLocked,
            'account_expired' => !$accountNonExpired,
            'credentials_expired' => !$credentialsNonExpired,
            'extra_fields' => [],
        ];

        $types = [
            'username' => PDO::PARAM_STR,
            'email' => PDO::PARAM_STR,
            'password' => PDO::PARAM_STR,
            'roles' => Types::JSON,
            'enabled' => PDO::PARAM_BOOL,
            'account_locked' => PDO::PARAM_BOOL,
            'account_expired' => PDO::PARAM_BOOL,
            'credentials_expired' => PDO::PARAM_BOOL,
            'extra_fields' => Types::JSON,
        ];

        $this->connection->insert($this->tableName, $data, $types);

        if (!$this->connection->isAutoCommit()) {
            $this->connection->commit();
        }

        $io = new SymfonyStyle($input, $output);
        $io->text(
            [
                sprintf('New user "<info>%s - %s</info>" was added successfully:', $username, $email),
                '',
                sprintf('Roles: <info>%s</info>', implode(', ', $roles)),
                sprintf('Password hash: <info>%s</info>', $password),
                '',
            ]
        );

        return self::SUCCESS;
    }
}