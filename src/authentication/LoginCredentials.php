<?php
/**
 * Wraps login credentials into an object.
 */
abstract class LoginCredentials {
    protected $userName;
    protected $password;
    
    /**
     * Gets value of user name
     *  
     * @return string
     */
    public function getUserName() {
        return $this->userName;
    }
    
    /**
     * Gets value of password
     * 
     * @return string
     */
    public function getPassword() {
        return $this->password;
    }
}