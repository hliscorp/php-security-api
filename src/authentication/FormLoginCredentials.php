<?php
require_once("LoginCredentials.php");

/**
 * Wraps credentials for form authentication into an object.
 */
class FormLoginCredentials extends LoginCredentials {
    private $rememberMe;
    
    /**
     * Sets up username & password.
     * 
     * @param string $paramUsername Name of POST parameter that holds user name.
     * @param string $paramPassword Name of POST parameter that holds password.
     * @throws AuthenticationException If username or password are empty.
     */
    public function __construct($paramUsername="username", $paramPassword="password") {
        if(empty($_POST[$paramUsername]) || empty($_POST[$paramPassword])) {
        	throw new AuthenticationException("Parameters are mandatory: $paramUsername, $paramPassword!");
        }
        $this->userName = $_POST[$paramUsername];
        $this->password = $_POST[$paramPassword];
    }
    
    /**
     * Sets optional remember me flag
     * 
     * @param mixed $paramRememberMe Name of POST parameter that holds remember me flag.
     * @throws AuthenticationException If value of remember me is not safely convertible to boolean.
     */
    
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
    
    /**
     * Gets value of remember me
     * 
     * @return NULL|boolean Null if flag does not exist, boolean in any other situation.
     */
    public function getRememberMe() {
        return $this->rememberMe;
    }
}