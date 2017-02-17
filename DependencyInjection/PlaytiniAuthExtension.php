<?php

namespace Playtini\Bundle\AuthBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class PlaytiniAuthExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @param ContainerBuilder $container
     */
    public function prepend(ContainerBuilder $container)
    {
        $config = [
            'clients' => [
                'google' => [
                    // must be "google" - it activates that type!
                    'type' => 'google',
                    // add and configure client_id and client_secret in parameters.yml
                    'client_id' =>  $container->getParameter('google_app_id'),
                    'client_secret' => $container->getParameter('google_app_secret'),
                    // a route name you'll create
                    'redirect_route' => 'playtini_auth_connect_google_check',
                    'redirect_params' => [],
                    // Optional value for sending access_type parameter. More detail: https://developers.google.com/identity/protocols/OAuth2WebServer#offline
                    'access_type' => 'online',
                    // Optional value for sending hd parameter. More detail: https://developers.google.com/accounts/docs/OAuth2Login#hd-param
                    'hosted_domain' => $container->getParameter('google_app_domain'),
                    // whether to check OAuth2 "state": defaults to true
                    'use_state' => false
                ]
            ]
        ];
        $container->prependExtensionConfig('knpu_oauth2_client', $config);
    }

    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');
    }
}
