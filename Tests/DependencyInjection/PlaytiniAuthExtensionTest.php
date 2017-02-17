<?php

namespace Playtini\Tests\Bundle\AppBundle\DependencyInjection;

use Playtini\Bundle\AuthBundle\DependencyInjection\PlaytiniAuthExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * @covers \Playtini\Bundle\AuthBundle\DependencyInjection\PlaytiniAuthExtension
 */
class PlaytiniAuthExtensionTest extends \PHPUnit_Framework_TestCase
{
    public function testPrepend()
    {
        $container = new ContainerBuilder();
        $container->setParameter('google_app_id', '123asd321');
        $container->setParameter('google_app_secret', 'asd123dsa');
        $container->setParameter('google_app_domain', 'playtini.ua');
        $loader = new PlaytiniAuthExtension();
        $loader->prepend($container);
        $expected = [
            'clients' => [
                'google' => [
                    'type' => 'google',
                    'client_id' =>  '123asd321',
                    'client_secret' => 'asd123dsa',
                    'redirect_route' => 'playtini_auth_connect_google_check',
                    'redirect_params' => [],
                    'access_type' => 'online',
                    'hosted_domain' => 'playtini.ua',
                    'use_state' => false
                ]
            ]
        ];
        $this->assertEquals([0 => $expected], $container->getExtensionConfig('knpu_oauth2_client'));
    }

    public function testLoad()
    {
        $container = new ContainerBuilder();
        $loader = new PlaytiniAuthExtension();
        $config = [];
        $loader->load([$config], $container);

        $expectedServices = [
            'playtini.auth.model.user_manager',
            'playtini.auth.security.google_authenticator',
            'playtini.auth.security.api_key_user_provider',
            'playtini.auth.security.api_key_authenticator',
            'twig.security_extension',
        ];
        $this->assertEquals($expectedServices, array_keys($container->getDefinitions()));
    }
}
