<?php
namespace Lucinda\WebSecurity;

require_once("AuthenticationException.php");
require_once("AuthenticationResult.php");
require("UserAuthenticationXML.php");

/**
 * Encapsulates authentication via XML ACL
 */
class XMLAuthentication
{
    private $xml;
    private $persistenceDrivers;
    
    /**
     * Creates a form authentication object.
     *
     * @param \SimpleXMLElement $xml
     * @param PersistenceDriver[] $persistenceDrivers List of PersistentDriver entries that allow authenticated state to persist between requests.
     * @throws AuthenticationException If one of persistenceDrivers entries is not a PersistentDriver
     */
    public function __construct(\SimpleXMLElement $xml, array $persistenceDrivers = array()): void
    {
        // check argument that it's instance of PersistenceDriver
        foreach ($persistenceDrivers as $persistentDriver) {
            if (!($persistentDriver instanceof PersistenceDriver)) {
                throw new AuthenticationException("Items must be instanceof PersistenceDriver");
            }
        }
        
        // save pointers
        $this->xml = $xml;
        $this->persistenceDrivers = $persistenceDrivers;
    }
    
    /**
     * Performs a login operation:
     * - queries XML for an user id based on credentials
     * - saves user_id in persistence drivers (if any)
     *
     * @param string $username Value of user name
     * @param string $password Value of user password
     * @return AuthenticationResult Encapsulates result of login attempt.
     * @throws AuthenticationException If POST parameters are invalid.
     */
    public function login(string $username, string $password): AuthenticationResult
    {
        $dao = new UserAuthenticationXML($this->xml);
        $userID = $dao->login($username, $password);
        if (empty($userID)) {
            $result = new AuthenticationResult(AuthenticationResultStatus::LOGIN_FAILED);
            return $result;
        } else {
            // saves in persistence drivers
            foreach ($this->persistenceDrivers as $persistenceDriver) {
                $persistenceDriver->save($userID);
            }
            // returns result
            $result = new AuthenticationResult(AuthenticationResultStatus::LOGIN_OK);
            $result->setUserID($userID);
            return $result;
        }
    }
    
    /**
     * Performs a logout operation:
     * - removes user id from persistence drivers (if any)
     *
     * @return AuthenticationResult
     */
    public function logout(): AuthenticationResult
    {
        // detect user_id from persistence drivers
        $userID = null;
        foreach ($this->persistenceDrivers as $persistentDriver) {
            $userID = $persistentDriver->load();
            if ($userID) {
                break;
            }
        }
        if (!$userID) {
            $result = new AuthenticationResult(AuthenticationResultStatus::LOGOUT_FAILED);
            return $result;
        } else {
            // clears data from persistence drivers
            foreach ($this->persistenceDrivers as $persistentDriver) {
                $persistentDriver->clear($userID);
            }
            
            // returns result
            $result = new AuthenticationResult(AuthenticationResultStatus::LOGOUT_OK);
            return $result;
        }
    }
}
