<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\TokenExpiredException;

/**
 * Encapsulates a driver that persists unique user identifier into a crypted "remember me" cookie variable.
 */
class RememberMePersistenceDriver implements PersistenceDriver
{
    private $token;
    
    private $parameterName;
    private $expirationTime;
    private $isHttpOnly;
    private $isSecure;
    
    /**
     * Creates a persistence driver object.
     *
     * @param string $salt Strong password to use for crypting. (Check: http://randomkeygen.com/)
     * @param string $parameterName Name of SESSION parameter that holds cypted unique user identifier.
     * @param integer $expirationTime Time by which cookie expires (cannot be renewed), in seconds.
     * @param string $isHttpOnly  Whether or not cookie should be using HTTP-only.
     * @param string $isSecure Whether or not cookie should be using HTTPS-only.
     * @param string $ip Value of REMOTE_ADDR attribute, unless ignored.
     */
    public function __construct(string $salt, string $parameterName, int $expirationTime, string $isHttpOnly = false, string $isSecure = false, string $ip=""): void
    {
        $this->token = new SynchronizerToken($ip, $salt);
        $this->parameterName = $parameterName;
        $this->expirationTime = $expirationTime;
        $this->isHttpOnly = $isHttpOnly;
        $this->isSecure = $isSecure;
    }
    
    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return mixed Unique user identifier (usually an integer) or NULL if none exists.
     */
    public function load()
    {
        if (empty($_COOKIE[$this->parameterName])) {
            return;
        }
        
        try {
            return $this->token->decode($_COOKIE[$this->parameterName]);
        } catch (\Exception $e) {
            // delete bad cookie
            setcookie($this->parameterName, "", time()+$this->expirationTime, "/", "", $this->isSecure, $this->isHttpOnly);
            setcookie($this->parameterName, false);
            unset($_COOKIE[$this->parameterName]);
            // rethrow exception, unless it's token expired
            if ($e instanceof TokenExpiredException) {
                return;
            } else {
                throw $e;
            }
        }
    }
    
    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param mixed $userID Unique user identifier (usually an integer)
     */
    public function save($userID): void
    {
        $token = $this->token->encode($userID, $this->expirationTime);
        setcookie($this->parameterName, $token, time()+$this->expirationTime, "/", "", $this->isSecure, $this->isHttpOnly);
        $_COOKIE[$this->parameterName] = $token;
    }
    
    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        setcookie($this->parameterName, "", time()+$this->expirationTime, "/", "", $this->isSecure, $this->isHttpOnly);
        setcookie($this->parameterName, false);
        unset($_COOKIE[$this->parameterName]);
    }
}
