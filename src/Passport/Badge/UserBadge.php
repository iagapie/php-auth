<?php

declare(strict_types=1);

namespace IA\Auth\Passport\Badge;

use IA\Auth\Exception\UserNotFoundException;
use IA\Auth\User\UserInterface;
use LogicException;

class UserBadge implements BadgeInterface
{
    /**
     * @var callable|null
     */
    protected $userLoader;

    /**
     * @var UserInterface|null
     */
    protected ?UserInterface $user = null;

    /**
     * Initializes the user badge.
     *
     * You must provide a $userIdentifier. This is a unique string representing the
     * user for this authentication (e.g. the email if authentication is done using
     * email + password; or a string combining email+company if authentication is done
     * based on email *and* company name). This string can be used for e.g. login throttling.
     *
     * Optionally, you may pass a user loader. This callable receives the $userIdentifier
     * as argument and must return a UserInterface object (otherwise a UserNotFoundException
     * is thrown). If this is not set, the default user provider will be used with
     * $userIdentifier as username.
     *
     * @param string $userIdentifier
     * @param callable|null $userLoader
     */
    public function __construct(protected string $userIdentifier, ?callable $userLoader = null)
    {
        $this->userLoader = $userLoader;
    }

    /**
     * @return UserInterface
     */
    public function getUser(): UserInterface
    {
        if (null === $this->user) {
            if (null === $this->userLoader) {
                throw new LogicException('No user loader is configured in UserBadge.');
            }

            $this->user = ($this->userLoader)($this->userIdentifier);

            if (!$this->user instanceof UserInterface) {
                throw new UserNotFoundException(
                    $this->getUserIdentifier(),
                    \sprintf('Username "%s" does not exist.', $this->getUserIdentifier())
                );
            }
        }

        return $this->user;
    }

    /**
     * @return string
     */
    public function getUserIdentifier(): string
    {
        return $this->userIdentifier;
    }

    /**
     * @return callable|null
     */
    public function getUserLoader(): ?callable
    {
        return $this->userLoader;
    }

    /**
     * @param callable $userLoader
     */
    public function setUserLoader(callable $userLoader): void
    {
        $this->userLoader = $userLoader;
    }

    /**
     * {@inheritDoc}
     */
    public function isResolved(): bool
    {
        return true;
    }
}