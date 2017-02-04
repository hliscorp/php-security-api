<?php
class SessionPersistenceDriver implements PersistenceDriver {
	private $current_ip;
	private $current_time;
	
	private $parameterName;
	private $expirationTime;
	private $isHttpOnly;
	private $isSecure;
	
	public function __construct($parameterName = "uid", $expirationTime = 0, $isHttpOnly = false, $isSecure = false) {
		$this->current_ip = (isset($_SERVER["REMOTE_ADDR"])?$_SERVER["REMOTE_ADDR"]:"");
		$this->current_time = microtime(true);
		
		$this->parameterName = $parameterName;
		$this->expirationTime = $expirationTime;
		$this->isHttpOnly = $isHttpOnly;
		$this->isSecure = $isSecure;
	}
	
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
		if($this->expirationTime && ($this->current_time-$_SESSION["time"])>$this->expirationTime) {
			session_regenerate_id(true);
			$_SERVER = array();
			return;
		}
		
		// update last time
		$_SESSION["time"] = $this->current_time;
		
		return $_SESSION[$this->parameterName];
	}
	
	public function save($userID) {
		// regenerate id when elevating privileges
		session_regenerate_id();
		// save params to session
		$_SESSION[$this->parameterName] = $userID;
		$_SESSION["ip"] = $this->current_ip;
		$_SESSION["time"] = $this->current_time;
	}
}