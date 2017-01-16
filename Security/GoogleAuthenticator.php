<?php

namespace Playtini\Bundle\AuthBundle\Security;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\Provider\GoogleClient;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use KnpU\OAuth2ClientBundle\Security\Helper\FinishRegistrationBehavior;
use KnpU\OAuth2ClientBundle\Security\Helper\PreviousUrlHelper;
use KnpU\OAuth2ClientBundle\Security\Helper\SaveAuthFailureMessage;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Playtini\Bundle\AuthBundle\Entity\User;
use Playtini\Bundle\AuthBundle\Model\UserManager;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class GoogleAuthenticator extends SocialAuthenticator
{
    use PreviousUrlHelper;
    use SaveAuthFailureMessage;
    use FinishRegistrationBehavior;

    /** @var ClientRegistry */
    private $clientRegistry;

    /** @var RouterInterface */
    private $router;

    /** @var string */
    private $googleDomain;

    /** @var array */
    private $allowedUsers;

    /** @var UserManager */
    private $userManager;

    /** @var array */
    private $adminUsers;

    public function __construct(
        ClientRegistry $clientRegistry,
        RouterInterface $router,
        string $googleDomain = 'example.com',
        string $allowedUsers = 'user1,user2',
        UserManager $userManager,
        string $adminUsersString = ''
    ) {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->googleDomain = $googleDomain;
        $this->allowedUsers = array_values(array_filter(array_map('trim', explode(',', $allowedUsers))));
        $this->userManager = $userManager;
        if ($adminUsersString) {
            $this->adminUsers = array_values(array_filter(array_map('trim', explode(',', $adminUsersString))));
        }
    }

    public function getCredentials(Request $request)
    {
        if ($request->getPathInfo() != $this->router->generate('playtini_auth_connect_google_check')) {
            // skip authentication unless we're on this URL!
            return null;
        }
        try {
            $client = $this->clientRegistry->getClient('google');
            $token = $client->getAccessToken();

            return $token;
        } catch (IdentityProviderException $e) {
            // you could parse the response to see the problem
            throw $e;
        }
    }

    /**
     * @param AccessToken $credentials
     * @param UserProviderInterface $userProvider
     * @return User|null
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        /** @var GoogleClient $googleClient */
        $googleClient = $this->clientRegistry->getClient('google');
        $googleUser = $googleClient->fetchUserFromToken($credentials);

        // 1) have they logged in with Google before? Easy!
        $existingUser = $this->userManager->findOneByGoogleId($googleUser->getId());
        if ($existingUser) {
            $this->setUserRoles($existingUser);

            return $existingUser;
        }

        // 2) do we have a matching user by email?
        $email = $googleUser->getEmail();
        $user = $this->userManager->findOneByEmail($email);

        // 3) no user? Redirect to finish registration
        if (!$user) {
            $username = preg_replace('#@.*#', '', $email);
            if (
                substr($email, -strlen($this->googleDomain) - 1) !== '@' . $this->googleDomain ||
                !in_array($username, $this->allowedUsers)
            ) {
                throw new AuthenticationException();
            }

            $user = $this->userManager->createUser();
            $user
                ->setEnabled(true)
                ->setEmail($email)
                ->setUsername($username);
        }

        // make sure the Google user is set
        $user->setGoogleId($googleUser->getId());
        $this->userManager->saveUser($user);

        $this->setUserRoles($user);

        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
        // do nothing - the fact that the access token worked means that
        // our app has been authorized with Google
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $this->saveAuthenticationErrorToSession($request, $exception);
        $loginUrl = $this->router->generate('playtini_auth_security_logout');

        return new RedirectResponse($loginUrl);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $url = $this->getPreviousUrl($request, $providerKey);
        if (!$url) {
            $url = $this->router->generate('homepage');
        }

        return new RedirectResponse($url);
    }

    /**
     * Called when an anonymous user tries to access an protected page.
     *
     * In our app, this is never actually called, because there is only *one* "entry_point" per firewall and in security.yml,
     * we're using app.form_login_authenticator as the entry point (so it's start() method is the one that's called).
     * @param Request $request
     * @param AuthenticationException $authException
     * @return Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        // not called in our app, but if it were, redirecting to the login page makes sense
        $url = $this->router->generate('playtini_auth_security_login');

        return new RedirectResponse($url);
    }

    /**
     * Set user's roles on fly
     *
     * @param User $user
     */
    private function setUserRoles(User $user)
    {
        if ($this->adminUsers && in_array($user->getUsername(), $this->adminUsers)) {
            $user->setRoles([User::ROLE_ADMIN]);
        }
    }
}
