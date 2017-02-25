<?php
/**
 * Enum that contains all available authentication statuses.
 */
class AuthenticationResultStatus {
	const OK = 1;
	const LOGIN_FAILED = 2;
	const LOGOUT_FAILED = 3;
}

/**
 * Encapsulates authentication response
 */
class AuthenticationResult {
    private $status;
    private $callbackURI;
    private $userID;

    public function __construct($status) {
    	$this->status = $status;
    }
    
    /**
     * Gets authentication status.
     *
     * @return string
     */
    public function getStatus() {
        return $this->status;
    }
    
    /**
     * Sets callback URL.
     * 
     * @param string $callbackURI
     */
    public function setCallbackURI($callbackURI) {
    	$this->callbackURI = $callbackURI;
    }

    /**
     * Gets callback URI
     *
     * @return string
     */
    public function getCallbackURI() {
        return $this->callbackURI;
    }
    
    /**
     * Sets user unique identifier
     * 
     * @param mixed $userID
     */
    public function setUserID($userID) {
    	$this->userID = $userID;
    }
    
    /**
     * Gets user unique identifier.
     * 
     * @return mixed
     */
    public function getUserID() {
    	return $this->userID;
    }
}