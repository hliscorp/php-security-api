<?php
require_once("UserAuthenticationDAO.php");
require_once("AuthenticationException.php");
require_once("AuthenticationResult.php");
require_once("FormLoginCredentials.php");

/**
 * Encapsulates authentication via data sent by POST through a html form 
 */
class FormAuthentication {
	private $dao;
	private $persistenceDrivers;
	
	/**
	 * Creates a form authentication object.
	 * 
	 * @param UserAuthenticationDAO $dao Forwards operations to database via a DAO.
	 * @param PersistenceDriver[] $persistenceDrivers List of PersistentDriver entries that allow authenticated state to persist between requests.
	 * @throws AuthenticationException If one of persistenceDrivers entries is not a PersistentDriver
	 */
	public function __construct(UserAuthenticationDAO $dao, $persistenceDrivers = array()) {
		// check argument that it's instance of PersistenceDriver
		foreach($persistenceDrivers as $persistentDriver) {
			if(!($persistentDriver instanceof PersistenceDriver)) throw new AuthenticationException("Items must be instanceof PersistenceDriver");
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
	 * @param string $userNameParameter Name of POST parameter that holds user name.
	 * @param string $passwordParameter Name of POST parameter that holds password.
	 * @param string $rememberMeParameter Name of POST parameter that holds remember me (optional).
	 * @return AuthenticationResult Encapsulates result of login attempt.
	 * @throws AuthenticationException If POST parameters are invalid.
	 */
	public function login($userNameParameter, $passwordParameter, $rememberMeParameter) {
		$credentials = new FormLoginCredentials($userNameParameter, $passwordParameter);
		if(isset($_POST[$rememberMeParameter])) {
			$credentials->setRememberMe($rememberMeParameter);	
		} else {
			foreach($this->persistenceDrivers as $i=>$persistenceDriver) {
				if($persistenceDriver instanceof RememberMePersistenceDriver) {
					unset($this->persistenceDrivers[$i]);
					break;
				}
			}
		}
		$userID = $this->dao->login($credentials); 
		if(empty($userID)) {
			$result = new AuthenticationResult(AuthenticationResultStatus::LOGIN_FAILED);
			return $result;
		} else {
			// saves in persistence drivers
			foreach($this->persistenceDrivers as $persistenceDriver) {
				$persistenceDriver->save($userID);
			}
			// returns result
			$result = new AuthenticationResult(AuthenticationResultStatus::OK);
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
	public function logout() {
		// detect user_id from persistence drivers
		$userID = null;
		foreach($this->persistenceDrivers as $persistentDriver) {
			$userID = $persistentDriver->load();
			if($userID) break;
		}
		if(!$userID) {
			$result = new AuthenticationResult(AuthenticationResultStatus::LOGOUT_FAILED);
			return $result;
		} else {
			// should throw an exception if user is not already logged in
			$this->dao->logout($userID);
			
			// clears data from persistence drivers 		
			foreach($this->persistenceDrivers as $persistentDriver) {
				$persistentDriver->clear($userID);
			}	
			
			// returns result
			$result = new AuthenticationResult(AuthenticationResultStatus::OK);
			return $result;
		}
	}
}