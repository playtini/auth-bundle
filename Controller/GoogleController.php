<?php

namespace Playtini\Bundle\AuthBundle\Controller;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Response;

class GoogleController extends Controller
{
    /**
     * Link to this controller to start the "connect" process
     *
     * @param Request $request
     * @return Response
     */
    public function loginAction(Request $request)
    {
        $link = $this->get('oauth2.registry')->getClient('google')->getOAuth2Provider()->getAuthorizationUrl();

        if (!$request->cookies->get('logout')) {
            return RedirectResponse::create($link);
        }

        $response = new Response();
        $response->headers->clearCookie('logout');

        return $this->render('AuthBundle::login.html.twig', [
            'link' => $link
        ], $response);
    }

    /**
     * After going to Facebook, you're redirect back here
     * because this is the "redirect_route" you configured
     * in services.yml
     *
     * @param Request $request
     * @return Response
     */
    public function loginCheckAction(Request $request)
    {
        // ** if you want to *authenticate* the user, then
        // leave this method blank and create a Guard authenticator
    }

    public function logoutAction()
    {
        // will never be executed
    }

    /**
     * @return RedirectResponse
     */
    public function forceLogoutAction()
    {
        $response = new RedirectResponse($this->get('router')->generate('mailer_auth_security_logout'));
        $response->headers->setCookie(new Cookie('logout', 1, '+1 hour'));

        return $response;
    }
}
