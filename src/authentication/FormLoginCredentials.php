<?php
class FormLoginCredentials extends LoginCredentials {
    private $rememberMe;
    
    public function __construct($paramUsername="username", $paramPassword="password") {
        if(empty($_POST[$paramUsername]) || empty($_POST[$paramPassword])) throw new AuthenticationException("Parameters are mandatory: $paramUsername, $paramPassword!");
        $this->userName = $_POST[$paramUsername];
        $this->password = $_POST[$paramPassword];
    }
    
    public function setRememberMe($value=true) {
        $this->rememberMe = $value;
    }
    
    public function getRememberMe() {
        return $this->rememberMe;
    }
}