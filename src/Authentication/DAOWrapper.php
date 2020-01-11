<?php
namespace Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Authentication\DAO\UserAuthenticationDAO;
use Lucinda\WebSecurity\Authentication\DAO\Authentication;
use Lucinda\WebSecurity\Authentication\Form\FormRequestValidator;
use Lucinda\WebSecurity\Authentication\Form\LoginRequest;
use Lucinda\WebSecurity\Authentication\Form\LogoutRequest;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Lucinda\WebSecurity\Authentication\Form\LoginThrottlerHandler;
use Lucinda\WebSecurity\ClassFinder;
use Lucinda\WebSecurity\Authentication\Form\LoginThrottler;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Binds DAOAuthentication @ SECURITY-API to settings from configuration.xml @ SERVLETS-API then performs login/logout if it matches paths @ xml via database.
 */
class DAOWrapper extends Wrapper
{
    private $driver;

    /**
     * Creates an object.
     *
     * @param \SimpleXMLElement $xml XML holding information relevant to authentication (above all via security.authentication tag)
     * @param Request $request Encapsulated client request data.
     * @param CsrfTokenDetector $csrfTokenDetector Driver performing CSRF validation
     * @param PersistenceDriver[] $persistenceDrivers Drivers where authenticated state is persisted (eg: session, remember me cookie).
     * @throws ConfigurationException If POST parameters are not provided when logging in or DAO classes are misconfigured.
     * @throws TokenException If CSRF checks fail
     */
    public function __construct(\SimpleXMLElement $xml, Request $request, CsrfTokenDetector $csrfTokenDetector, array $persistenceDrivers)
    {
        // starts dao-based form authentication
        $this->driver = new Authentication($this->getDAO($xml), $persistenceDrivers);

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
     * Gets DAO where authentication is performed
     *
     * @param \SimpleXMLElement $xml
     * @throws ConfigurationException
     * @return UserAuthenticationDAO
     */
    private function getDAO(\SimpleXMLElement $xml): UserAuthenticationDAO
    {
        $className = (string) $xml->authentication->form["dao"];
        $classFinder = new ClassFinder((string) $xml["dao_path"]);
        $className = $classFinder->find($className);
        $authenticationDaoObject = new $className();
        if (!($authenticationDaoObject instanceof UserAuthenticationDAO)) {
            throw new ConfigurationException("Class must be instance of UserAuthenticationDAO: ".$className);
        }
        return $authenticationDaoObject;
    }
    
    /**
     * Gets DAO where login attempts are counted and throttled, if necessary
     *
     * @param \SimpleXMLElement $xml
     * @param Request $request
     * @param LoginRequest $loginRequest
     * @throws ConfigurationException
     * @return LoginThrottler
     */
    private function getThrottler(\SimpleXMLElement $xml, Request $request, LoginRequest $loginRequest): LoginThrottler
    {
        $throttlerClassName = (string) $xml->authentication->form["throttler"];
        $classFinder = new ClassFinder((string) $xml["dao_path"]);
        $throttlerClassName = $classFinder->find($throttlerClassName);
        $throttlerObject = new $throttlerClassName($request, $loginRequest->getUsername());
        if (!($throttlerObject instanceof LoginThrottler)) {
            throw new ConfigurationException("Class must be instance of LoginThrottler: ".$throttlerClassName);
        }
        return $throttlerObject;
    }

    /**
     * Logs user in authentication driver.
     *
     * @param LoginRequest $request Encapsulates login request data.
     */
    private function login(LoginRequest $request): void
    {
        $result = null;
        
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
    private function logout(LogoutRequest $request): void
    {
        // set result
        $result = $this->driver->logout();
        $this->setResult($result, $request->getDestinationPage(), $request->getDestinationPage());
    }
}
