<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

/**
 * Encapsulates a driver that persists unique user identifier into sessions.
 */
class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private string $current_ip;
    private string $parameterName;
    private int $expirationTime;
    private bool $isHttpOnly;
    private bool $isSecure;
    
    /**
     * Creates a persistence driver object.
     *
     * @param string $parameterName Name of SESSION parameter that holds unique user identifier.
     * @param integer $expirationTime Time by which session expires no matter what, in seconds.
     * @param bool $isHttpOnly Whether session should be using HTTP-only cookies.
     * @param bool $isSecure Whether session should be using HTTPS-only cookies.
     * @param string $ip Value of REMOTE_ADDR parameter, unless ignored.
     */
    public function __construct(string $parameterName, int $expirationTime = 0, bool $isHttpOnly = false, bool $isSecure = false, string $ip="")
    {
        $this->current_ip = $ip;
        $this->parameterName = $parameterName;
        $this->expirationTime = $expirationTime;
        $this->isHttpOnly = $isHttpOnly;
        $this->isSecure = $isSecure;
    }
    
    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param int|string $userID Unique user identifier (usually an integer)
     */
    public function save(int|string $userID): void
    {
        $_SESSION[$this->parameterName] = $userID;
        $_SESSION["ip"] = $this->current_ip;
        $_SESSION["time"] = time()+$this->expirationTime;
    }

    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return int|string|null Unique user identifier (usually an integer) or NULL if none exists.
     * @throws HijackException
     */
    public function load(): int|string|null
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
            return null;
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
            return null;
        }
        
        // update last time
        $_SESSION["time"] = time()+$this->expirationTime;
        
        return $_SESSION[$this->parameterName];
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
