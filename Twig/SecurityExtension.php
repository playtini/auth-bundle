<?php

namespace Playtini\Bundle\AuthBundle\Twig;

use Playtini\Bundle\AuthBundle\Security\ApiKeyUserProvider;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

class SecurityExtension extends \Twig_Extension
{
    /** @var ApiKeyUserProvider */
    private $apiKeyUserProvider;

    /** @var TokenStorage */
    private $tokenStorage;

    public function __construct(ApiKeyUserProvider $apiKeyUserProvider, TokenStorage $tokenStorage)
    {
        $this->apiKeyUserProvider = $apiKeyUserProvider;
        $this->tokenStorage = $tokenStorage;
    }

    public function getFunctions()
    {
        return array(
            new \Twig_SimpleFunction('api_key', [$this, 'apiKey']),
        );
    }

    public function apiKey()
    {
        $username = $this->tokenStorage->getToken()->getUsername();
        if (!$username) {
            return '';
        }

        $hash = $this->apiKeyUserProvider->getHash($username);
        $apiKey = sprintf('%s~%s', $username, $hash);

        return $apiKey;
    }

    public function getName()
    {
        return 'security_extension';
    }
}
