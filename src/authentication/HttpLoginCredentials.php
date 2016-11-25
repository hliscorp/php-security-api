<?php
class HttpLoginCredentials extends LoginCredentials {
    public function __construct($paramUsername="username", $paramPassword="password") {
        if(empty($_SERVER['PHP_AUTH_USER'])) throw new AuthenticationException("Parameters are mandatory: username, password!");
        $this->userName = $_SERVER['PHP_AUTH_USER'];
        $this->password = $_SERVER['PHP_AUTH_PW'];
    }
}