<?php
namespace Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Authentication\DAO\UserAuthenticationDAO;
use Lucinda\WebSecurity\Authentication\DAO\Authentication;
use Lucinda\WebSecurity\Authentication\Form\LoginRequest;
use Lucinda\WebSecurity\Authentication\Form\LogoutRequest;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\Authentication\Form\LoginThrottler;
use Lucinda\WebSecurity\ConfigurationException;
use Lucinda\WebSecurity\Token\RegenerationException;

/**
 * Binds DAOAuthentication @ SECURITY-API to settings from configuration.xml @ SERVLETS-API then performs login/logout if it matches paths @ xml via database.
 */
class DAOWrapper extends FormWrapper
{
    private Authentication $driver;

    /**
     * Creates an object.
     *
     * @param \SimpleXMLElement $xml XML holding information relevant to authentication (above all via security.authentication tag)
     * @param Request $request Encapsulated client request data.
     * @param CsrfTokenDetector $csrfTokenDetector Driver performing CSRF validation
     * @param PersistenceDriver[] $persistenceDrivers Drivers where authenticated state is persisted (eg: session, remember me cookie).
     * @throws ConfigurationException
     * @throws Form\Exception
     * @throws TokenException
     * @throws EncryptionException
     * @throws RegenerationException
     */
    public function __construct(\SimpleXMLElement $xml, Request $request, CsrfTokenDetector $csrfTokenDetector, array $persistenceDrivers)
    {
        $this->driver = new Authentication($this->getDAO($xml), $persistenceDrivers);
        $this->process($xml, $request, $csrfTokenDetector);
    }

    /**
     * Gets DAO where authentication is performed
     *
     * @param \SimpleXMLElement $xml
     * @return UserAuthenticationDAO
     * @throws ConfigurationException
     */
    private function getDAO(\SimpleXMLElement $xml): UserAuthenticationDAO
    {
        $className = (string) $xml->authentication->form["dao"];
        if (!$className) {
            throw new ConfigurationException("Attribute 'dao' is mandatory for 'form' tag");
        }
        return new $className();
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
    protected function login(LoginRequest $request): void
    {
        // set result
        $result = $this->driver->login(
            $request->getUsername(),
            $request->getPassword(),
            $request->getRememberMe()
        );
                
        $this->setResult($result, $request->getSourcePage(), $request->getDestinationPage());
    }

    /**
     * Logs user out authentication driver.
     *
     * @param LogoutRequest $request Encapsulates logout request data.
     */
    protected function logout(LogoutRequest $request): void
    {
        // set result
        $result = $this->driver->logout();
        $this->setResult($result, $request->getDestinationPage(), $request->getDestinationPage());
    }
}
