<?php

namespace Playtini\Bundle\AuthBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * ApiController
 */
class ApiController extends Controller
{
    /**
     * Provides key that can be used to connect to other services with AuthBundle
     *
     * @return JsonResponse {api_key: string}
     */
    public function keyAction()
    {
        $username = $this->getUser()->getUsername();
        $apiKey = $this->get('playtini.auth.security.api_key_user_provider')->getHash($username);

        return JsonResponse::create([
            'api_key' => $username . '~' . $apiKey,
        ]);
    }
}
