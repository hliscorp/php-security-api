<?php
require_once("UserAuthenticationDAO.php");
require_once("AuthenticationException.php");
require_once("FormLoginCredentials.php");
require_once("PersistenceDriver.php");

class FormAuthentication {
	private $userAuthenticationDAO;
	private $persistenceDrivers;
	
	public function __construct(UserAuthenticationDAO $dao, $persistenceDrivers = array()) {
		// check argument that it's instance of PersistenceDriver
		foreach($persistenceDrivers as $persistentDriver) {
			if(!($persistentDriver instanceof PersistenceDriver)) throw new AuthenticationException("Items must be instanceof PersistenceDriver");
		}
		
		// save pointers
		$this->userAuthenticationDAO = $dao;
		$this->persistenceDrivers = $persistenceDrivers;
	}
	
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
	}
	
	public function logout($userID) {
		// should throw an exception if user is not already logged in
		$this->userAuthenticationDAO->logout($userID);
		
		// clears data from persistence drivers 		
		foreach($this->persistenceDrivers as $persistentDriver) {
			$persistentDriver->clear($userID);
		}
	}
}