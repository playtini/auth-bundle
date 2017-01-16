<?php

namespace Playtini\Tests\Bundle\AppBundle\Entity;

use Playtini\Bundle\AuthBundle\Entity\User;

/**
 * @covers \Playtini\Bundle\AuthBundle\Entity\User
 */
class UserTest extends \PHPUnit_Framework_TestCase
{
    /** @var User */
    private $user;

    public function setUp()
    {
        $this->user = new class extends User {};
    }

    public function tearDown()
    {
        unset($this->user);
    }

    public function testId()
    {
        $this->assertEquals(time(), $this->user->getCreatedAt()->getTimestamp(), 2);
        $this->assertEquals(time(), $this->user->getLastActiveAt()->getTimestamp(), 2);
        $this->assertNull($this->user->getId());
    }

    public function testCreatedAt()
    {
        $this->assertEquals(time(), $this->user->getCreatedAt()->getTimestamp(), 2);
        $createdAt = new \DateTime('-4 hours');
        $this->user->setCreatedAt($createdAt);
        $this->assertSame($createdAt, $this->user->getCreatedAt());
    }

    public function testLastActiveAt()
    {
        $this->assertEquals(time(), $this->user->getLastActiveAt()->getTimestamp(), 2);
        $lastActiveAt = new \DateTime('-4 hours');
        $this->user->setLastActiveAt($lastActiveAt);
        $this->assertSame($lastActiveAt, $this->user->getLastActiveAt());
    }

    public function testGoogleId()
    {
        $this->assertNull($this->user->getGoogleId());
        $googleId = '123asd321';
        $this->user->setGoogleId($googleId);
        $this->assertSame($googleId, $this->user->getGoogleId());
    }

    public function testGoogleAccessToken()
    {
        $this->assertNull($this->user->getGoogleAccessToken());
        $googleAccessToken = '123asd321';
        $this->user->setGoogleAccessToken($googleAccessToken);
        $this->assertSame($googleAccessToken, $this->user->getGoogleAccessToken());
    }

    public function testUsername()
    {
        $this->assertNull($this->user->getUsername());
        $username = '123asd321';
        $this->user->setUsername($username);
        $this->assertSame($username, $this->user->getUsername());
    }

    public function testEnabled()
    {
        $this->assertNull($this->user->getEnabled());
        $this->user->setEnabled(true);
        $this->assertTrue($this->user->getEnabled());
    }

    public function testEmail()
    {
        $this->assertNull($this->user->getEmail());
        $email = '123asd321';
        $this->user->setEmail($email);
        $this->assertSame($email, $this->user->getEmail());
    }

    public function testGetRoles()
    {
        $this->assertEquals(['ROLE_USER'], $this->user->getRoles());
    }

    public function testGetPassword()
    {
        $this->assertNull($this->user->getPassword());
    }

    public function testGetSalt()
    {
        $this->assertNull($this->user->getSalt());
    }

    public function testEraseCredentials()
    {
        $this->assertNull($this->user->eraseCredentials());
    }
}
