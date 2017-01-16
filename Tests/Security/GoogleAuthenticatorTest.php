<?php

namespace Playtini\Tests\Bundle\AppBundle\Security;


use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2Client;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Token\AccessToken;
use Playtini\Bundle\AuthBundle\Entity\User;
use Playtini\Bundle\AuthBundle\Model\UserManager;
use Playtini\Bundle\AuthBundle\Security\GoogleAuthenticator;
use Prophecy\Argument;
use Prophecy\Prophecy\ObjectProphecy;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * @covers \Playtini\Bundle\AuthBundle\Security\GoogleAuthenticator
 */
class GoogleAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    /** @var GoogleAuthenticator */
    private $authenticator;

    /** @var ClientRegistry|ObjectProphecy */
    private $clientRegistry;

    /** @var RouterInterface|ObjectProphecy */
    private $router;

    /** @var string */
    private $googleDomain = 'example.com';

    /** @var array */
    private $allowedUsers = 'user1,user2';

    /** @var UserManager|ObjectProphecy */
    private $userManager;

    /** @var array */
    private $adminUsers = 'user3,user4';

    protected function setUp()
    {
        $this->clientRegistry = $this->prophesize(ClientRegistry::class);
        $this->router = $this->prophesize(RouterInterface::class);
        $this->userManager = $this->prophesize(UserManager::class);

        $this->authenticator = new GoogleAuthenticator(
            $this->clientRegistry->reveal(),
            $this->router->reveal(),
            $this->googleDomain,
            $this->allowedUsers,
            $this->userManager->reveal(),
            $this->adminUsers
        );
    }

    public function testGetCredentialsSkip()
    {
        $request = Request::create('/some/path');

        $this->router->generate('playtini_auth_connect_google_check')->shouldBeCalledTimes(1)->willReturn('/another/path');

        $this->assertNull($this->authenticator->getCredentials($request));
    }

    public function testGetCredentials()
    {
        $request = Request::create('/some/path');
        $this->router->generate('playtini_auth_connect_google_check')->shouldBeCalledTimes(1)->willReturn('/some/path');
        $client = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($client);
        $token = 'some_token';
        $client->getAccessToken()->shouldBeCalledTimes(1)->willReturn($token);

        $result = $this->authenticator->getCredentials($request);

        $this->assertSame($token, $result);
    }

    /**
     * @expectedException \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function testGetCredentialsException()
    {
        $request = Request::create('/some/path');
        $this->router->generate('playtini_auth_connect_google_check')->shouldBeCalledTimes(1)->willReturn('/some/path');
        $client = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($client);
        $client->getAccessToken()->shouldBeCalledTimes(1)->willThrow(new IdentityProviderException(1, 2, 3));

        $this->authenticator->getCredentials($request);
    }

    public function testGetUser_UserRegisteredViaGoogle()
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser(['id' => '123dsa213']);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $user = (new User())->setUsername('user1');
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn($user);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
    }

    public function testGetUser_UserRegisteredViaGoogleNotAdminUser()
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser(['id' => '123dsa213']);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $user = (new User())->setGoogleAccessToken('token')->setUsername('user1');
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn($user);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
        $this->assertEquals([User::ROLE_USER], $result->getRoles());
    }

    public function testGetUser_UserRegisteredViaGoogleAdmin()
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser(['id' => '123dsa213']);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $user = (new User())->setGoogleAccessToken('token')->setUsername('user3');
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn($user);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
        $this->assertEquals([User::ROLE_ADMIN], $result->getRoles());
    }

    /**
     * @expectedException \Symfony\Component\Security\Core\Exception\AuthenticationException
     */
    public function testGetUser_CreateNewUserInvalidEmilException()
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser([
            'id' => '123dsa213',
            'emails' => [0 => ['value' => 'email@test.com']]
        ]);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn(null);
        $this->userManager->findOneByEmail('email@test.com')->shouldBeCalledTimes(1)->willReturn(null);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals('user', $result);
    }

    public function testGetUser_CreateNewUser()
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser([
            'id' => '123asd321',
            'emails' => [0 => ['value' => 'user1@example.com']]
        ]);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $this->userManager->findOneByGoogleId('123asd321')->shouldBeCalledTimes(1)->willReturn(null);
        $this->userManager->findOneByEmail('user1@example.com')->shouldBeCalledTimes(1)->willReturn(null);
        $user = new User();
        $this->userManager->createUser()->shouldBeCalledTimes(1)->willReturn($user);
        $user->setEnabled(true)->setEmail('user1@example.com')->setUsername('user1')->setGoogleId('123asd321');
        /** @noinspection PhpParamsInspection */
        $this->userManager->saveUser(Argument::that(function(User $user) {
            $this->assertTrue($user->getEnabled());
            $this->assertEquals('user1@example.com', $user->getEmail());
            $this->assertEquals('user1', $user->getUsername());
            $this->assertEquals('123asd321', $user->getGoogleId());
            $this->assertEquals(time(), $user->getCreatedAt()->getTimestamp(), 2);
            $this->assertEquals(time(), $user->getLastActiveAt()->getTimestamp(), 2);
            return true;
        }))->shouldBeCalledTimes(1);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
    }

    public function testGetUser_RegisteredNotByGoogle_NotAdmin()
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser([
            'id' => '123dsa213',
            'emails' => [0 => ['value' => 'email@test.com']]
        ]);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn(null);
        $user = (new User())->setUsername('user2')->setCreatedAt(new \DateTime('2016-01-01'))->setLastActiveAt(new \DateTime('2016-10-10'));
        $this->userManager->findOneByEmail('email@test.com')->shouldBeCalledTimes(1)->willReturn($user);
        $this->userManager->saveUser(Argument::that(function(User $arg) use ($user) {
            $this->assertEquals($arg, $user);
            return true;
        }))->shouldBeCalledTimes(1);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
        $this->assertEquals([User::ROLE_USER], $result->getRoles());
    }

    public function testGetUser_RegisteredNotByGoogle_Admin()
    {
        $credentials = new AccessToken(['access_token' => 'token']);
        $googleClient = $this->prophesize(OAuth2Client::class);
        $this->clientRegistry->getClient('google')->shouldBeCalledTimes(1)->willReturn($googleClient);
        $googleUser = new GoogleUser([
            'id' => '123dsa213',
            'emails' => [0 => ['value' => 'email@test.com']]
        ]);
        $googleClient->fetchUserFromToken($credentials)->shouldBeCalledTimes(1)->willReturn($googleUser);
        $this->userManager->findOneByGoogleId('123dsa213')->shouldBeCalledTimes(1)->willReturn(null);
        $user = (new User())->setUsername('user3')->setCreatedAt(new \DateTime('2016-01-01'))->setLastActiveAt(new \DateTime('2016-10-10'));
        $this->userManager->findOneByEmail('email@test.com')->shouldBeCalledTimes(1)->willReturn($user);
        $this->userManager->saveUser(Argument::that(function(User $arg) use ($user) {
            $this->assertEquals($arg, $user);
            return true;
        }))->shouldBeCalledTimes(1);

        $result = $this->authenticator->getUser($credentials, $this->prophesize(UserProviderInterface::class)->reveal());

        $this->assertEquals($user, $result);
        $this->assertEquals([User::ROLE_ADMIN], $result->getRoles());
    }

    public function testCheckCredential()
    {
        $result =$this->authenticator->checkCredentials('credentials', $this->prophesize(UserInterface::class)->reveal());

        $this->assertTrue($result);
    }

    public function testOnAuthenticationFailure()
    {
        $request = new Request();
        $session = $this->prophesize(Session::class);
        $request->setSession($session->reveal());
        $session->set(Security::AUTHENTICATION_ERROR, new AuthenticationException())->shouldBeCalledTimes(1);
        $this->router->generate('playtini_auth_security_logout')->shouldBeCalledTimes(1)->willReturn('/login/url');

        $result = $this->authenticator->onAuthenticationFailure($request, new AuthenticationException());

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertEquals('/login/url', $result->getTargetUrl());
    }

    public function testOnAuthenticationSuccess_NoPreviousUrl()
    {
        $providerKey = 'provider_key';
        $request = new Request();
        $session = $this->prophesize(Session::class);
        $request->setSession($session->reveal());
        $session->get('_security.'.$providerKey.'.target_path')->shouldBeCalledTimes(1)->willReturn(null);
        $this->router->generate('homepage')->shouldBeCalledTimes(1)->willReturn('/homepage');

        $result = $this->authenticator->onAuthenticationSuccess(
            $request,
            $this->prophesize(TokenInterface::class)->reveal(),
            $providerKey
        );

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertEquals('/homepage', $result->getTargetUrl());
    }

    public function testOnAuthenticationSuccess_WithPreviousUrl()
    {
        $providerKey = 'provider_key';
        $request = new Request();
        $session = $this->prophesize(Session::class);
        $request->setSession($session->reveal());
        $session->get('_security.'.$providerKey.'.target_path')->shouldBeCalledTimes(1)->willReturn('/prev/page');

        $result = $this->authenticator->onAuthenticationSuccess(
            $request,
            $this->prophesize(TokenInterface::class)->reveal(),
            $providerKey
        );

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertEquals('/prev/page', $result->getTargetUrl());
    }

    public function testStart()
    {
        $request = new Request();
        $this->router->generate('playtini_auth_security_login')->shouldBeCalledTimes(1)->willReturn('/homepage');

        $result = $this->authenticator->start($request);

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertEquals('/homepage', $result->getTargetUrl());
    }
}
