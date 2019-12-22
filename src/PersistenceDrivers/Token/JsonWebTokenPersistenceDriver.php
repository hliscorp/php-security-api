<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\Token;

use Lucinda\WebSecurity\Token\JsonWebToken;
use Lucinda\WebSecurity\Token\RegenerationException;
use Lucinda\WebSecurity\Token\ExpiredException;
use Lucinda\WebSecurity\Token\JsonWebTokenPayload;

/**
 * Encapsulates a PersistenceDriver that uses JsonWebToken to authenticate users.
 */
class JsonWebTokenPersistenceDriver extends PersistenceDriver
{
    private $expirationTime;
    private $regenerationTime;
    private $tokenDriver;
    
    /**
     * Creates a persistence driver object.
     *
     * @param string $salt Strong password to use for crypting. (Check: http://randomkeygen.com/)
     * @param integer $expirationTime Time by which token expires (can be renewed), in seconds.
     * @param string $regenerationTime Time by which token is renewed, in seconds.
     */
    public function __construct(string $salt, int $expirationTime = 3600, string $regenerationTime = 60)
    {
        $this->tokenDriver = new JsonWebToken($salt);
        $this->expirationTime = $expirationTime;
        $this->regenerationTime = $regenerationTime;
    }
    
    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return mixed Unique user identifier (usually an integer) or NULL if none exists.
     */
    public function load()
    {
        $this->setAccessToken();
        if (!$this->accessToken) {
            return;
        }
        $userID = null;
        // decode token
        try {
            $payload = $this->tokenDriver->decode($this->accessToken, $this->regenerationTime);
            $userID = $payload->getApplicationId();
        } catch (RegenerationException $e) {
            $userID = $e->getPayload()->getApplicationId();
            $this->save($userID);
        } catch (ExpiredException $e) {
            $this->accessToken = null;
        }
        return $userID;
    }
    
    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param mixed $userID Unique user identifier (usually an integer)
     */
    public function save($userID): void
    {
        $payload = new JsonWebTokenPayload();
        $payload->setApplicationId($userID);
        $payload->setStartTime(time());
        $payload->setEndTime(time()+$this->expirationTime);
        $this->accessToken = $this->tokenDriver->encode($payload);
    }
    
    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        $this->accessToken = null;
    }
}
