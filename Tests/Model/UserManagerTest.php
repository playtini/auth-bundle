<?php

namespace Playtini\Tests\Bundle\AppBundle\Model;

use Doctrine\Common\Persistence\Mapping\ClassMetadata;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\Common\Persistence\ObjectRepository;
use Playtini\Bundle\AuthBundle\Entity\User;
use Playtini\Bundle\AuthBundle\Model\UserManager;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;

class TestUser extends User
{
}

/**
 * @covers \Playtini\Bundle\AuthBundle\Model\UserManager
 */
class UserManagerTest extends \PHPUnit_Framework_TestCase
{
    const USER_CLASS = TestUser::class;
    /** @var UserManager */
    private $userManager;
    /** @var ObjectManager|ObjectProphecy */
    private $om;
    /** @var ObjectRepository|ObjectProphecy */
    private $repository;

    public function setUp()
    {
        $this->om = $this->prophesize(ObjectManager::class);
        $this->repository = $this->prophesize(ObjectRepository::class);
        $class = $this->prophesize(ClassMetadata::class);

        $this->om->getRepository(self::USER_CLASS)->shouldBeCalledTimes(1)->willReturn($this->repository);
        $this->om->getClassMetadata(self::USER_CLASS)->shouldBeCalledTimes(1)->willReturn($class);
        $class->getName()->willReturn(self::USER_CLASS);

        $this->userManager = new UserManager($this->om->reveal(), self::USER_CLASS);
    }

    public function testGetClass()
    {
        $this->assertEquals(self::USER_CLASS, $this->userManager->getClass());
    }

    public function testCreateUser()
    {
        $user = $this->userManager->createUser();
        $this->assertEquals(time(), $user->getCreatedAt()->getTimestamp(), 2);
        $this->assertEquals(time(), $user->getLastActiveAt()->getTimestamp(), 2);
    }

    public function testSaveUser()
    {
        $user = new TestUser();

        $this->om->persist($user)->shouldBeCalledTimes(1);
        $this->om->flush()->shouldBeCalledTimes(1);

        $this->userManager->saveUser($user);
    }

    public function testFinOneByGoogleId()
    {
        $user = new TestUser();
        $googleId = '123asd321';

        $this->repository->findOneBy(['googleId' => $googleId])->shouldBeCalledTimes(1)->willReturn($user);

        $this->assertSame($user, $this->userManager->findOneByGoogleId($googleId));
    }

    public function testFindOneByEmail()
    {
        $user = new TestUser();
        $email = 'email@test.com';

        $this->repository->findOneBy(['email' => $email])->shouldBeCalledTimes(1)->willReturn($user);

        $this->assertSame($user, $this->userManager->findOneByEmail($email));
    }
}
