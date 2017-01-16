<?php

namespace Playtini\Tests\Bundle\AppBundle\Twig;

use Playtini\Bundle\AuthBundle\Security\ApiKeyUserProvider;
use Playtini\Bundle\AuthBundle\Twig\SecurityExtension;
use Prophecy\Prophecy\ObjectProphecy;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class SecurityExtensionTest extends \PHPUnit_Framework_TestCase
{
    /** @var SecurityExtension */
    private $extension;

    /** @var ApiKeyUserProvider|ObjectProphecy */
    private $apiKeyUserProvider;

    /** @var TokenStorage|ObjectProphecy */
    private $tokenStorage;

    protected function setUp()
    {
        $this->apiKeyUserProvider = $this->prophesize(ApiKeyUserProvider::class);
        $this->tokenStorage = $this->prophesize(TokenStorage::class);

        $this->extension = new SecurityExtension(
            $this->apiKeyUserProvider->reveal(),
            $this->tokenStorage->reveal()
        );
    }

    public function testApiKey_NoUsername()
    {
        $token = $this->prophesize(TokenInterface::class);
        $token->getUsername()->willReturn('');
        $this->tokenStorage->getToken()->shouldBeCalledTimes(1)->willReturn($token);

        $result = $this->extension->apiKey();

        $this->assertSame('', $result);
    }

    public function testApiKey()
    {
        $token = $this->prophesize(TokenInterface::class);
        $token->getUsername()->shouldBeCalledTimes(1)->willReturn('username');
        $this->tokenStorage->getToken()->shouldBeCalledTimes(1)->willReturn($token);
        $this->apiKeyUserProvider->getHash('username')->shouldBeCalledTimes(1)->willReturn('hash');

        $result = $this->extension->apiKey();

        $this->assertSame('username~hash', $result);
    }

    public function testGetName()
    {
        $this->assertEquals('security_extension', $this->extension->getName());
    }

    public function testGetFunctions()
    {
        $functions = $this->extension->getFunctions();

        $this->assertCount(1, $functions);
        $this->assertEquals('api_key', $functions[0]->getName());
    }
}
