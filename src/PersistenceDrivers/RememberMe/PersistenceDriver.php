<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\ExpiredException;

/**
 * Encapsulates a driver that persists unique user identifier into a crypted "remember me" cookie variable.
 */
class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private SynchronizerToken $token;
    
    private string $parameterName;
    private int $expirationTime;
    private bool $isHttpOnly;
    private bool $isSecure;
    
    /**
     * Creates a persistence driver object.
     *
     * @param string $salt Strong password to use for crypting. (Check: http://randomkeygen.com/)
     * @param string $parameterName Name of SESSION parameter that holds cypted unique user identifier.
     * @param integer $expirationTime Time by which cookie expires (cannot be renewed), in seconds.
     * @param bool $isHttpOnly  Whether or not cookie should be using HTTP-only.
     * @param bool $isSecure Whether or not cookie should be using HTTPS-only.
     * @param string $ip Value of REMOTE_ADDR attribute, unless ignored.
     */
    public function __construct(string $salt, string $parameterName, int $expirationTime, bool $isHttpOnly = false, bool $isSecure = false, string $ip="")
    {
        $this->token = new SynchronizerToken($ip, $salt);
        $this->parameterName = $parameterName;
        $this->expirationTime = $expirationTime;
        $this->isHttpOnly = $isHttpOnly;
        $this->isSecure = $isSecure;
    }

    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param int|string $userID Unique user identifier (usually an integer)
     * @throws \Lucinda\WebSecurity\Token\EncryptionException
     */
    public function save(int|string $userID): void
    {
        $token = $this->token->encode($userID, $this->expirationTime);
        setcookie($this->parameterName, $token, time()+$this->expirationTime, "/", "", $this->isSecure, $this->isHttpOnly);
        $_COOKIE[$this->parameterName] = $token;
    }
    
    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return int|string|null Unique user identifier (usually an integer) or NULL if none exists.
     * @throws \Exception
     */
    public function load(): int|string|null
    {
        if (empty($_COOKIE[$this->parameterName])) {
            return null;
        }
        
        try {
            return $this->token->decode($_COOKIE[$this->parameterName]);
        } catch (\Exception $e) {
            // delete bad cookie
            setcookie($this->parameterName, "", time()+$this->expirationTime, "/", "", $this->isSecure, $this->isHttpOnly);
            setcookie($this->parameterName, false);
            unset($_COOKIE[$this->parameterName]);
            // rethrow exception, unless it's token expired
            if ($e instanceof ExpiredException) {
                return null;
            } else {
                throw $e;
            }
        }
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
