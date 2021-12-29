<?php
namespace Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Authentication\Form\FormRequestValidator;
use Lucinda\WebSecurity\Authentication\Form\LoginRequest;
use Lucinda\WebSecurity\Authentication\Form\LoginThrottler;
use Lucinda\WebSecurity\Authentication\Form\LoginThrottlerHandler;
use Lucinda\WebSecurity\Authentication\Form\LogoutRequest;
use Lucinda\WebSecurity\ConfigurationException;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Token\Exception as TokenException;

/**
 * Abstract form-based authentication mechanism regardless of where users are checked (database or access control lists)
 */
abstract class FormWrapper extends Wrapper
{
    /**
     * Processes authentication request
     *
     * @param \SimpleXMLElement $xml
     * @param Request $request
     * @param CsrfTokenDetector $csrfTokenDetector
     * @throws ConfigurationException
     * @throws Form\Exception
     * @throws TokenException
     * @throws \Lucinda\WebSecurity\Token\EncryptionException
     * @throws \Lucinda\WebSecurity\Token\RegenerationException
     */
    protected function process(\SimpleXMLElement $xml, Request $request, CsrfTokenDetector $csrfTokenDetector): void
    {
        // setup class properties
        $validator = new FormRequestValidator($xml, $request);

        // checks if a login action was requested, in which case it forwards object to driver
        if ($loginRequest = $validator->login()) {
            // check csrf token
            $parameters = $request->getParameters();
            if (empty($parameters["csrf"]) || !$csrfTokenDetector->isValid($parameters["csrf"], 0)) {
                throw new TokenException("CSRF token is invalid or missing!");
            }

            // performs login, using throttler if defined
            $loginThrottlerHandler = new LoginThrottlerHandler($this->getThrottler($xml, $request, $loginRequest));
            $this->result = $loginThrottlerHandler->start($request);
            if ($this->result) {
                return;
            }
            $this->login($loginRequest);
            $loginThrottlerHandler->end($this->result);
        }

        // checks if a logout action was requested, in which case it forwards object to driver
        if ($logoutRequest = $validator->logout()) {
            $this->logout($logoutRequest);
        }
    }

    /**
     * Gets DAO where login attempts are counted and throttled, if necessary
     *
     * @param \SimpleXMLElement $xml
     * @param Request $request
     * @param LoginRequest $loginRequest
     * @return LoginThrottler
     * @throws ConfigurationException
     */
    private function getThrottler(\SimpleXMLElement $xml, Request $request, LoginRequest $loginRequest): LoginThrottler
    {
        $throttlerClassName = (string) $xml->authentication->form["throttler"];
        if (!$throttlerClassName) {
            throw new ConfigurationException("Attribute 'throttler' is mandatory for 'form' tag");
        }
        return new $throttlerClassName($request, $loginRequest->getUsername());
    }

    /**
     * Logs user in authentication driver.
     *
     * @param LoginRequest $request Encapsulates login request data.
     */
    abstract protected function login(LoginRequest $request): void;

    /**
     * Logs user out authentication driver.
     *
     * @param LogoutRequest $request Encapsulates logout request data.
     */
    abstract protected function logout(LogoutRequest $request): void;
}