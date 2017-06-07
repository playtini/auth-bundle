<?php

namespace Playtini\Tests\Bundle\AppBundle\Security;

use Playtini\Bundle\AuthBundle\Security\ApiKeyAuthenticator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * @covers \Playtini\Bundle\AuthBundle\Security\ApiKeyAuthenticator
 */
class ApiKeyAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    /** @var Request */
    private $request;

    /** @var ApiKeyAuthenticator */
    private $authenticator;

    protected function setUp()
    {
        $this->request = new Request();
        $this->authenticator = new ApiKeyAuthenticator();
    }

    public function testCreateToken(): void
    {
        $this->request->headers->set('X-Api-Key', '123');

        $token = $this->authenticator->createToken($this->request, 'testkey');

        $this->assertInstanceOf(PreAuthenticatedToken::class, $token);
        $this->assertEquals('testkey', $token->getProviderKey());
        $this->assertEquals('123', $token->getCredentials());
    }

    public function testCreateToken_Request()
    {
        $this->request->request->set('apikey', '123');

        $token = $this->authenticator->createToken($this->request, 'testkey');

        $this->assertInstanceOf(PreAuthenticatedToken::class, $token);
        $this->assertEquals('testkey', $token->getProviderKey());
        $this->assertEquals('123', $token->getCredentials());
    }

    public function testCreateToken_Query()
    {
        $this->request->query->set('apikey', '123');

        $token = $this->authenticator->createToken($this->request, 'testkey');

        $this->assertInstanceOf(PreAuthenticatedToken::class, $token);
        $this->assertEquals('testkey', $token->getProviderKey());
        $this->assertEquals('123', $token->getCredentials());
    }

    /**
     * @expectedException \Symfony\Component\Security\Core\Exception\BadCredentialsException
     * @expectedExceptionMessage No API key found
     */
    public function testCreateToken_NoApiKey(): void
    {
        $this->authenticator->createToken($this->request, 'testkey');
    }

    public function testOnAuthenticationFailure(): void
    {
        $result = $this->authenticator->onAuthenticationFailure(new Request(), new AuthenticationException('Auth failure'));

        $expected = JsonResponse::create([
            'code' => 401,
            'message' => 'Auth failure'
        ], 401);

        $this->assertEquals($expected, $result);
    }
}
