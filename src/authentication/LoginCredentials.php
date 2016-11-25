<?php
abstract class LoginCredentials {
    protected $userName;
    protected $password;
    
    public function getUserName() {
        return $this->userName;
    }
    
    public function getPassword() {
        return $this->password;
    }
}