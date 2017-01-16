<?php

namespace Playtini\Tests\Bundle\AppBundle\Security;

use Playtini\Bundle\AuthBundle\Security\ApiKeyAuthenticator;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;

/**
 * @covers \Playtini\Bundle\AuthBundle\Security\ApiKeyAuthenticator
 */
class ApiKeyAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    public function testCreateToken()
    {
        $request = $this->prophesize(Request::class);
        $headers = $this->prophesize(ParameterBag::class);
        $request->headers = $headers;

        $headers->get('X-Api-Key')->shouldBeCalledTimes(1)->willReturn('123');

        $authenticator = new ApiKeyAuthenticator();
        $token = $authenticator->createToken($request->reveal(), 'testkey');

        $this->assertInstanceOf(PreAuthenticatedToken::class, $token);
        $this->assertEquals('testkey', $token->getProviderKey());
        $this->assertEquals('123', $token->getCredentials());
    }

    public function testCreateTokenRequest()
    {
        $request = $this->prophesize(Request::class);
        $headers = $this->prophesize(ParameterBag::class);
        $request->headers = $headers;
        $requestRequest = $this->prophesize(ParameterBag::class);
        $request->request = $requestRequest;

        $headers->get('X-Api-Key')->shouldBeCalledTimes(1)->willReturn(null);
        $requestRequest->get('apikey')->shouldBeCalledTimes(1)->willReturn('123');

        $authenticator = new ApiKeyAuthenticator();
        $token = $authenticator->createToken($request->reveal(), 'testkey');

        $this->assertInstanceOf(PreAuthenticatedToken::class, $token);
        $this->assertEquals('testkey', $token->getProviderKey());
        $this->assertEquals('123', $token->getCredentials());
    }

    public function testCreateTokenQuery()
    {
        $request = $this->prophesize(Request::class);
        $headers = $this->prophesize(ParameterBag::class);
        $request->headers = $headers;
        $requestRequest = $this->prophesize(ParameterBag::class);
        $request->request = $requestRequest;
        $requestQuery = $this->prophesize(ParameterBag::class);
        $request->query = $requestQuery;

        $headers->get('X-Api-Key')->shouldBeCalledTimes(1)->willReturn(null);
        $requestRequest->get('apikey')->shouldBeCalledTimes(1)->willReturn(null);
        $requestQuery->get('apikey')->shouldBeCalledTimes(1)->willReturn('123');

        $authenticator = new ApiKeyAuthenticator();
        $token = $authenticator->createToken($request->reveal(), 'testkey');

        $this->assertInstanceOf(PreAuthenticatedToken::class, $token);
        $this->assertEquals('testkey', $token->getProviderKey());
        $this->assertEquals('123', $token->getCredentials());
    }

    /**
     * @expectedException \Symfony\Component\Security\Core\Exception\BadCredentialsException
     * @expectedExceptionMessage No API key found
     */
    public function testCreateTokenNoApiKey()
    {
        $request = $this->prophesize(Request::class);
        $headers = $this->prophesize(ParameterBag::class);
        $request->headers = $headers;
        $requestRequest = $this->prophesize(ParameterBag::class);
        $request->request = $requestRequest;
        $requestQuery = $this->prophesize(ParameterBag::class);
        $request->query = $requestQuery;

        $headers->get('X-Api-Key')->shouldBeCalledTimes(1)->willReturn(null);
        $requestRequest->get('apikey')->shouldBeCalledTimes(1)->willReturn(null);
        $requestQuery->get('apikey')->shouldBeCalledTimes(1)->willReturn(null);

        $authenticator = new ApiKeyAuthenticator();
        $authenticator->createToken($request->reveal(), 'testkey');
    }
}
