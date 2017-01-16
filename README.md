Playtini Auth Bundle
====================

Implementation of common authentication logic

Installation
------------

1) Use composer

Add parameters to `app/config/parameters.yml.dist`

```yml
parameters:
    google_app_id:     something.apps.googleusercontent.com
    google_app_secret: your_secret
    google_app_domain: yourdomain.com
    google_app_users: user1,user2
```

You may add parameters to env-map:

```
"google_app_id": "GOOGLE_APP_ID",
"google_app_secret": "GOOGLE_APP_SECRET",
"google_app_domain": "GOOGLE_APP_DOMAIN",
"google_app_users": "GOOGLE_APP_USERS",
```

Install

```sh
composer require playtini/auth-bundle
```

2) Add **PlaytiniAuthBundle** and **KnpUOAuth2ClientBundle** to `app/AppKernel.php`

```php
// app/AppKernel.php
new \KnpU\OAuth2ClientBundle\KnpUOAuth2ClientBundle(),
new \Playtini\Bundle\AuthBundle\PlaytiniAuthBundle()
```

3) Set `app/config/security.yml`

```yml
security:
    encoders:
        Symfony\Component\Security\Core\User\User:
            algorithm: bcrypt

    # http://symfony.com/doc/current/book/security.html#where-do-users-come-from-user-providers
    providers:
        database_users:
            entity: { class: 'Playtini\Bundle\AuthBundle\Entity\User', property: username }
        api_key_user_provider:
            id: playtini.auth.security.api_key_user_provider

    firewalls:
        dev:
            pattern:  ^/(_(profiler|wdt)|css|images|js)/
            security: false
        api:
            pattern: ^/api/(?!key\.json)
            stateless: true
            simple_preauth:
                authenticator: playtini.auth.security.api_key_authenticator
            provider: api_key_user_provider
        main:
            pattern: ^/
            logout:       true
            anonymous:    true
            guard:
                authenticators:
                    - playtini.auth.security.google_authenticator
                entry_point: playtini.auth.security.google_authenticator
            remember_me:
                secret: "%secret%"
                lifetime: 31536000 # 365 days in seconds
                path: /
                domain: ~ # Defaults to the current domain from $_SERVER
                #always_remember_me: true
    access_control:
        - { path: ^/login/, role: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/, roles: ROLE_USER }
```

4) Enable AuthBundle routing. Add to `app/config/routing.yml`

```yml
playtini_auth:
    resource: "@PlaytiniAuthBundle/Resources/config/routing/routing.yml"
```

5) Update your database schema
