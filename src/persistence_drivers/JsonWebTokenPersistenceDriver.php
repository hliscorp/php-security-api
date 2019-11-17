<?php
namespace Lucinda\WebSecurity;

require("TokenPersistenceDriver.php");
require(dirname(__DIR__)."/token/JsonWebToken.php");

/**
 * Encapsulates a PersistenceDriver that uses JsonWebToken to authenticate users.
 */
class JsonWebTokenPersistenceDriver extends TokenPersistenceDriver
{
    private $expirationTime;
    private $regenerationTime;
    private $tokenDriver;
    
    /**
     * Creates a persistence driver object.
     *
     * @param string $secret Strong password to use for crypting. (Check: http://randomkeygen.com/)
     * @param number $expirationTime Time by which token expires (can be renewed), in seconds.
     * @param string $regenerationTime Time by which token is renewed, in seconds.
     */
    public function __construct($secret, $expirationTime = 3600, $regenerationTime = 60)
    {
        $this->tokenDriver = new JsonWebToken($secret);
        $this->expirationTime = $expirationTime;
        $this->regenerationTime = $regenerationTime;
    }
    
    /**
     * {@inheritDoc}
     * @see PersistenceDriver::load()
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
        } catch (TokenRegenerationException $e) {
            $userID = $e->getPayload()->getApplicationId();
            $this->save($userID);
        } catch (TokenExpiredException $e) {
            $this->accessToken = null;
        }
        return $userID;
    }
    
    /**
     * {@inheritDoc}
     * @see PersistenceDriver::save()
     */
    public function save($userID)
    {
        $payload = new JsonWebTokenPayload();
        $payload->setApplicationId($userID);
        $payload->setStartTime(time());
        $payload->setEndTime(time()+$this->expirationTime);
        $this->accessToken = $this->tokenDriver->encode($payload);
    }
    
    /**
     * {@inheritDoc}
     * @see PersistenceDriver::clear()
     */
    public function clear()
    {
        $this->accessToken = null;
    }
}
