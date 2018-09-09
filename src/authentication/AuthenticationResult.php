<?php
namespace Lucinda\WebSecurity;
require_once("AuthenticationResultStatus.php");

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
     * @return AuthenticationResultStatus
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