<?php
namespace Lucinda\WebSecurity\Authentication;


/**
 * Encapsulates authentication response
 */
class Result
{
    private $status;
    private $callbackURI;
    private $userID;
    private $timePenalty;

    /**
     * Saves authentication result encapsulated by ResultStatus enum
     *
     * @param ResultStatus $status
     */
    public function __construct(ResultStatus $status)
    {
        $this->status = $status;
    }
    
    /**
     * Gets authentication status.
     *
     * @return ResultStatus
     */
    public function getStatus(): ResultStatus
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
