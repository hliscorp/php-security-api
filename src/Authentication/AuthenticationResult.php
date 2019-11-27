<?php
namespace Lucinda\WebSecurity;

require_once("AuthenticationResultStatus.php");

/**
 * Encapsulates authentication response
 */
class AuthenticationResult
{
    private $status;
    private $callbackURI;
    private $userID;
    private $timePenalty;

    /**
     * Saves authentication result encapsulated by AuthenticationResultStatus enum
     *
     * @param AuthenticationResultStatus $status
     */
    public function __construct(AuthenticationResultStatus $status): void
    {
        $this->status = $status;
    }
    
    /**
     * Gets authentication status.
     *
     * @return AuthenticationResultStatus
     */
    public function getStatus(): AuthenticationResultStatus
    {
        return $this->status;
    }
    
    /**
     * Sets callback URL.
     *
     * @param string $callbackURI
     */
    public function setCallbackURI(string $callbackURI): void
    {
        $this->callbackURI = $callbackURI;
    }

    /**
     * Gets callback URI
     *
     * @return string
     */
    public function getCallbackURI(): string
    {
        return $this->callbackURI;
    }
    
    /**
     * Sets user unique identifier
     *
     * @param mixed $userID
     */
    public function setUserID($userID): void
    {
        $this->userID = $userID;
    }
    
    /**
     * Gets user unique identifier.
     *
     * @return mixed
     */
    public function getUserID()
    {
        return $this->userID;
    }
    
    /**
     * Sets number of seconds client will be banned from authenticating
     * 
     * @param integer $timePenalty
     */
    public function setTimePenalty(int $timePenalty): void
    {
        $this->timePenalty = $timePenalty;
    }
    
    /**
     * Gets number of seconds client will be banned from authenticating
     *
     * @return integer
     */
    public function getTimePenalty(): int
    {
        return $this->timePenalty;
    }
}
