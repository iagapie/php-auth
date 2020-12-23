<?php

declare(strict_types=1);

namespace IA\Auth\Tools\Console\Command;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception;
use IA\Auth\Encoder\PasswordEncoderInterface;
use PDO;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

class UserPasswordCommand extends Command
{
    protected static $defaultName = 'user:password';

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
            ->setDescription('Change User Password.')
            ->addArgument(
                'username',
                InputArgument::REQUIRED
            )
            ->addArgument(
                'password',
                InputArgument::REQUIRED
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
        $password = (string)$input->getArgument('password');

        do {
            $password = $this->passwordEncoder->encode($password);
        } while ($this->passwordEncoder->needsRehash($password));

        $data = ['password' => $password];
        $criteria = ['username' => $username];
        $types = ['password' => PDO::PARAM_STR];

        $this->connection->update($this->tableName, $data, $criteria, $types);

        if (!$this->connection->isAutoCommit()) {
            $this->connection->commit();
        }

        $io = new SymfonyStyle($input, $output);
        $io->text(
            [
                sprintf('Password for "<info>%s</info>" was changed successfully.', $username),
                '',
            ]
        );

        return self::SUCCESS;
    }
}