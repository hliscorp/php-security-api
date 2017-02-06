<?php
require_once("UserAuthenticationDAO.php");
require_once("AuthenticationException.php");
require_once("FormLoginCredentials.php");
require_once("PersistenceDriver.php");

/**
 * Encapsulates authentication via data sent by POST through a html form 
 */
class FormAuthentication {
	private $userAuthenticationDAO;
	private $persistenceDrivers;
	
	/**
	 * Creates a form authentication object.
	 * 
	 * @param UserAuthenticationDAO $dao Forwards operations to database via a DAO.
	 * @param array $persistenceDrivers List of PersistentDriver entries that allow authenticated state to persist between requests.
	 * @throws AuthenticationException If one of persistenceDrivers entries is not a PersistentDriver
	 */
	public function __construct(UserAuthenticationDAO $dao, $persistenceDrivers = array()) {
		// check argument that it's instance of PersistenceDriver
		foreach($persistenceDrivers as $persistentDriver) {
			if(!($persistentDriver instanceof PersistenceDriver)) throw new AuthenticationException("Items must be instanceof PersistenceDriver");
		}
		
		// save pointers
		$this->userAuthenticationDAO = $dao;
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
	 * @return mixed Returns logged in user id (normally an integer)
	 */
	public function login($userNameParameter="username", $passwordParameter="password", $rememberMeParameter="remember_me") {
		$credentials = new FormLoginCredentials($userNameParameter, $passwordParameter);
		if(isset($_POST[$rememberMeParameter])) {
			$credentials->setRememberMe($rememberMeParameter);	
		}
		$userID = $this->userAuthenticationDAO->login($credentials); 
		if(!empty($userID)) {
			foreach($this->persistenceDrivers as $persistentDriver) {
				$persistentDriver->save($userID);
			}
		}
		return $userID;
	}
	
	/**
	 * Performs a logout operation:
	 * - informs DAO that user has logged out
	 * - removes user id from persistence drivers (if any)
	 * 
	 * @param mixed $userID Unique logged in user identifier (must be integer)
	 */
	public function logout($userID) {
		// should throw an exception if user is not already logged in
		$this->userAuthenticationDAO->logout($userID);
		
		// clears data from persistence drivers 		
		foreach($this->persistenceDrivers as $persistentDriver) {
			$persistentDriver->clear($userID);
		}
	}
}