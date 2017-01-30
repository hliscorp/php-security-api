<?php
require_once("UserAuthenticationDAO.php");
require_once("AuthenticationException.php");
require_once("FormLoginCredentials.php");

class FormAuthentication {
	private $userAuthenticationDAO;
	private $persistenceDriver;
	
	public function __construct(UserAuthenticationDAO $dao, PersistenceDriver $persistenceDriver = null) {
		$this->userAuthenticationDAO = $dao;
		$this->persistenceDriver = $persistenceDriver;
	}
	
	public function authenticate($userNameParameter="username", $passwordParameter="password", $rememberMeParameter="remember_me") {
		$credentials = new FormLoginCredentials($userNameParameter, $passwordParameter);
		if(isset($_POST[$rememberMeParameter])) {
			$credentials->setRememberMe($rememberMeParameter);	
		}
		$userID = $this->userAuthenticationDAO->login($credentials);
		if($this->persistenceDriver!==null) {
			$this->persistenceDriver->save($userID);
			// TODO: save remember me as well
		}
	}
}