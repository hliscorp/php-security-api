<?php
/**
 * Enum that contains all available authentication statuses.
 */
class AuthenticationResultStatus {
	const OK = 1;
	const LOGIN_FAILED = 2;
	const LOGOUT_FAILED = 3;
	const TOKEN_FAILED = 4;
}

/**
 * Encapsulates authentication response
 */
class AuthenticationResult {
    private $status;
    private $callbackURI;
    private $userID;
    private $token;

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
    
    /**
     * Sets access token.
     * 
     * @param string $token
     */
    public function setAccessToken($token) {
    	$this->token = $token;
    }
    
    /**
     * Gets access token
     * 
     * @return string
     */
    public function getAccessToken() {
    	return $this->token;
    }
}