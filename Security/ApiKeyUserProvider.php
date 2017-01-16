<?php

namespace Playtini\Bundle\AuthBundle\Security;

use Doctrine\Common\Persistence\ObjectManager;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Playtini\Bundle\AuthBundle\Entity\User;
use Symfony\Component\Security\Core\User\UserInterface;

class ApiKeyUserProvider implements UserProviderInterface
{
    /** @var ObjectManager */
    private $em;

    /** @var string */
    private $salt;

    public function __construct(ObjectManager $em, string $salt)
    {
        $this->em = $em;
        $this->salt = md5($salt);
    }

    public function getHash($username)
    {
        return md5(md5(md5($username) . $this->salt));
    }

    public function getUsernameForApiKey($apiKey)
    {
        if (strpos($apiKey, '~') === false) {
            return null;
        }
        list($username, $hash) = explode('~', $apiKey, 2);

        return ($hash == $this->getHash($username)) ? $username : null;
    }

    public function loadUserByUsername($username)
    {
        $repository = $this->em->getRepository('AuthBundle:User');

        return $repository->findOneBy(['username' => $username]);
    }

    public function refreshUser(UserInterface $user)
    {
        // $user is the User that you set in the token inside authenticateToken()
        // after it has been deserialized from the session

        // you might use $user to query the database for a fresh user
        // $id = $user->getId();
        // use $id to make a query

        // if you are *not* reading from a database and are just creating
        // a User object (like in this example), you can just return it
        return $user;
    }

    public function supportsClass($class)
    {
        return User::class === $class;
    }
}
