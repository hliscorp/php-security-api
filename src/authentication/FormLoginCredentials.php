<?php
require_once("LoginCredentials.php");

class FormLoginCredentials extends LoginCredentials {
    private $rememberMe;
    
    public function __construct($paramUsername="username", $paramPassword="password") {
        if(empty($_POST[$paramUsername]) || empty($_POST[$paramPassword])) throw new AuthenticationException("Parameters are mandatory: $paramUsername, $paramPassword!");
        $this->userName = $_POST[$paramUsername];
        $this->password = $_POST[$paramPassword];
    }
    
    public function setRememberMe($paramRememberMe=true) {
    	$value = null;
    	if($_POST[$paramRememberMe]==="0" || $_POST[$paramRememberMe]===false ||  $_POST[$paramRememberMe]===0) {
    		$value = false;
    	} else if($_POST[$paramRememberMe]==="1" || $_POST[$paramRememberMe]===true ||  $_POST[$paramRememberMe]===1) {
    		$value = true;
    	} else {
    		throw new AuthenticationException("Value of remember me parameter must be safely convertible to boolean!");
    	}
    	$this->rememberMe = $value;
    }
    
    public function getRememberMe() {
        return $this->rememberMe;
    }
}