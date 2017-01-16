<?php

namespace Playtini\Bundle\AuthBundle\Model;

use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use Playtini\Bundle\AuthBundle\Entity\User;

class UserManager
{
    /** @var ObjectManager */
    private $objectManager;

    /** @var string */
    private $class;

    /** @var ObjectRepository */
    private $repository;

    public function __construct(ObjectManager $objectManager, string $class)
    {
        $this->objectManager = $objectManager;
        $this->repository = $objectManager->getRepository($class);

        $metadata = $objectManager->getClassMetadata($class);
        $this->class = $metadata->getName();
    }

    public function getClass(): string
    {
        return $this->class;
    }

    public function saveUser(User $user)
    {
        $this->objectManager->persist($user);
        $this->objectManager->flush();
    }

    public function createUser(): User
    {
        $class = $this->getClass();
        $user = new $class;

        return $user;
    }

    /**
     * @param string $googleId
     * @return User|null
     */
    public function findOneByGoogleId(string $googleId)
    {
        return $this->repository->findOneBy(['googleId' => $googleId]);
    }

    /**
     * @param string $email
     * @return User|null
     */
    public function findOneByEmail(string $email)
    {
        return $this->repository->findOneBy(['email' => $email]);
    }
}
