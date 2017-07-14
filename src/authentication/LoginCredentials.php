<?php
/**
 * Wraps login credentials into an object.
 */
class LoginCredentials {
    protected $userName;
    protected $password;
    
    /**
     * Sets value of user name
     *  
     * @param string $userName
     */
    public function setUserName($userName) {
        $this->userName = $userName;
    }
    
    /**
     * Gets value of user name
     *  
     * @return string
     */
    public function getUserName() {
        return $this->userName;
    }
    
    /**
     * Sets value of user password
     *  
     * @param string $userPassword
     */
    public function setUserName($userPassword) {
        $this->userPassword = $userPassword;
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
