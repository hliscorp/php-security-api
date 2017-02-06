<?php
require_once("SecurityException.php");

/**
 * Encapsulates a driver that persists unique user identifier into sessions.
 */
class SessionPersistenceDriver implements PersistenceDriver {
	private $current_ip;
	
	private $parameterName;
	private $expirationTime;
	private $isHttpOnly;
	private $isSecure;
	
	/**
	 * Creates a persistence driver object.
	 * 
	 * @param string $parameterName Name of SESSION parameter that holds unique user identifier.
	 * @param number $expirationTime Time by which session expires no matter what, in seconds.
	 * @param string $isHttpOnly Whether or not session should be using HTTP-only cookies.
	 * @param string $isSecure Whether or not session should be using HTTPS-only cookies.
	 */
	public function __construct($parameterName = "uid", $expirationTime = 0, $isHttpOnly = false, $isSecure = false) {
		$this->current_ip = (isset($_SERVER["REMOTE_ADDR"])?$_SERVER["REMOTE_ADDR"]:"");
		
		$this->parameterName = $parameterName;
		$this->expirationTime = $expirationTime;
		$this->isHttpOnly = $isHttpOnly;
		$this->isSecure = $isSecure;
	}

	/**
	 * Loads logged in user's unique identifier from driver. Note: 
	 *
	 * @return mixed Unique user identifier (usually an integer) or NULL if none exists or session has expired.
	 * @throws SecurityException On session hijacking attempts
	 */
	public function load() {
		// start session, using security options if requested
		if(session_id() == "") {
			if($this->isHttpOnly) {
				ini_set("session.cookie_httponly", 1);
			}
			if($this->isSecure) {
				ini_set("session.cookie_secure",1);
			}
			session_start();
		}		
		
		// do nothing if session does not include uid
		if(empty($_SESSION[$this->parameterName])) {
			return;
		}
				
		// session hijacking prevention: session id is tied to a single ip
		if($this->current_ip!=$_SESSION["ip"]) {
			session_regenerate_id(true);
			$_SERVER = array();
			throw new SecurityException("Session hijacking attempt!");
		}
		
		// session fixation prevention: if session is accessed after expiration time, it is invalidated
		if($this->expirationTime && time()>$_SESSION["time"]) {
			session_regenerate_id(true);
			$_SERVER = array();
			return;
		}
		
		// update last time
		$_SESSION["time"] = time()+$this->expirationTime;
		
		return $_SESSION[$this->parameterName];
	}
	
	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::save()
	 */
	public function save($userID) {
		// regenerate id when elevating privileges
		session_regenerate_id(true);
		// save params to session
		$_SESSION[$this->parameterName] = $userID;
		$_SESSION["ip"] = $this->current_ip;
		$_SESSION["time"] = time()+$this->expirationTime;
	}
	
	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::clear()
	 */
	public function clear($userID) {
		$_SESSION = array();
		session_regenerate_id(true);
	}
}