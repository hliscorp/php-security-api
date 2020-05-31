<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\Token;

use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\RegenerationException;
use Lucinda\WebSecurity\Token\ExpiredException;

/**
 * Encapsulates a PersistenceDriver that employs SynchronizerToken to authenticate users.
 */
class SynchronizerTokenPersistenceDriver extends PersistenceDriver
{
    private $expirationTime;
    private $regenerationTime;
    private $tokenDriver;
    
    /**
     * Creates a persistence driver object.
     *
     * @param string $salt Strong password to use for crypting.
     * @param string $ip Value of REMOTE_ADDR attribute, unless ignored.
     * @param integer $expirationTime Time by which token expires (can be renewed), in seconds.
     * @param integer $regenerationTime Time by which token is renewed, in seconds.
     */
    public function __construct(string $salt, string $ip, int $expirationTime = 3600, int $regenerationTime = 60)
    {
        $this->tokenDriver = new SynchronizerToken($ip, $salt);
        $this->expirationTime = $expirationTime;
        $this->regenerationTime = $regenerationTime;
    }
    
    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param mixed $userID Unique user identifier (usually an integer)
     */
    public function save($userID): void
    {
        $this->accessToken = $this->tokenDriver->encode($userID, $this->expirationTime);
    }
    
    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return mixed Unique user identifier (usually an integer) or NULL if none exists.
     */
    public function load()
    {
        if (!$this->accessToken) {
            return;
        }
        $userID = null;
        // decode token
        try {
            $userID = $this->tokenDriver->decode($this->accessToken, $this->regenerationTime);
        } catch (RegenerationException $e) {
            $userID = $e->getPayload();
            $this->accessToken = $this->tokenDriver->encode($userID, $this->expirationTime);
        } catch (ExpiredException $e) {
            $this->accessToken = null;
            return;
        }
        return $userID;
    }
    
    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        $this->accessToken = "";
    }
}
