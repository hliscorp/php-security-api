<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

/**
 * Encapsulates a driver that persists unique user identifier into sessions.
 */
class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private $current_ip;
    
    private $parameterName;
    private $expirationTime;
    private $isHttpOnly;
    private $isSecure;
    
    /**
     * Creates a persistence driver object.
     *
     * @param string $parameterName Name of SESSION parameter that holds unique user identifier.
     * @param integer $expirationTime Time by which session expires no matter what, in seconds.
     * @param string $isHttpOnly Whether or not session should be using HTTP-only cookies.
     * @param string $isSecure Whether or not session should be using HTTPS-only cookies.
     * @param string $ip Value of REMOTE_ADDR parameter, unless ignored.
     */
    public function __construct(string $parameterName, int $expirationTime = 0, string $isHttpOnly = false, string $isSecure = false, string $ip=""): void
    {
        $this->current_ip = $ip;
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
        // start session, using security options if requested
        if (session_id() == "") {
            if ($this->isHttpOnly) {
                ini_set("session.cookie_httponly", 1);
            }
            if ($this->isSecure) {
                ini_set("session.cookie_secure", 1);
            }
            if ($this->expirationTime) {
                ini_set('session.gc_maxlifetime', $this->expirationTime);
                session_set_cookie_params($this->expirationTime);
            }
            session_start();
        }
        
        // do nothing if session does not include uid
        if (empty($_SESSION[$this->parameterName])) {
            return;
        }
        
        // session hijacking prevention: session id is tied to a single ip
        if ($this->current_ip!=$_SESSION["ip"]) {
            session_regenerate_id(true);
            $_SESSION = array();
            throw new HijackException("Session hijacking attempt!");
        }
        
        // session fixation prevention: if session is accessed after expiration time, it is invalidated
        if ($this->expirationTime && time()>$_SESSION["time"]) {
            session_regenerate_id(true);
            $_SESSION = array();
            return;
        }
        
        // update last time
        $_SESSION["time"] = time()+$this->expirationTime;
        
        return $_SESSION[$this->parameterName];
    }
    
    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param mixed $userID Unique user identifier (usually an integer)
     */
    public function save($userID): void
    {
        $_SESSION[$this->parameterName] = $userID;
        $_SESSION["ip"] = $this->current_ip;
        $_SESSION["time"] = time()+$this->expirationTime;
    }
    
    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        $_SESSION = array();
        session_regenerate_id(true);
    }
}
