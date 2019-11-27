<?php
namespace Lucinda\WebSecurity;

require("UserAuthenticationDAO.php");
require_once("AuthenticationException.php");
require_once("AuthenticationResult.php");

/**
 * Encapsulates authentication via data sent by POST through a html form
 */
class DAOAuthentication
{
    private $dao;
    private $persistenceDrivers;
    
    /**
     * Creates a form authentication object.
     *
     * @param UserAuthenticationDAO $dao Forwards operations to database via a DAO.
     * @param PersistenceDriver[] $persistenceDrivers List of PersistentDriver entries that allow authenticated state to persist between requests.
     * @throws AuthenticationException If one of persistenceDrivers entries is not a PersistentDriver
     */
    public function __construct(UserAuthenticationDAO $dao, array $persistenceDrivers = array()): void
    {
        // check argument that it's instance of PersistenceDriver
        foreach ($persistenceDrivers as $persistentDriver) {
            if (!($persistentDriver instanceof PersistenceDriver)) {
                throw new AuthenticationException("Items must be instanceof PersistenceDriver");
            }
        }
        
        // save pointers
        $this->dao = $dao;
        $this->persistenceDrivers = $persistenceDrivers;
    }
    
    /**
     * Performs a login operation:
     * - queries DAO for an user id based on credentials
     * - saves user_id in persistence drivers (if any)
     *
     * @param string $username Value of user name
     * @param string $password Value of user password
     * @param boolean $rememberMe Value of remember me option (if any)
     * @return AuthenticationResult Encapsulates result of login attempt.
     * @throws AuthenticationException If POST parameters are invalid.
     */
    public function login(string $username, string $password, bool $rememberMe=null): AuthenticationResult
    {
        // do no persist into RememberMePersistenceDriver unless "remember me" is active
        if (!$rememberMe) {
            foreach ($this->persistenceDrivers as $i=>$persistenceDriver) {
                if ($persistenceDriver instanceof RememberMePersistenceDriver) {
                    unset($this->persistenceDrivers[$i]);
                    break;
                }
            }
        }
        
        // perform login
        $userID = $this->dao->login($username, $password);
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
     * - informs DAO that user has logged out
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
            // should throw an exception if user is not already logged in
            $this->dao->logout($userID);
            
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
