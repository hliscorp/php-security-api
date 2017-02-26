<?php
require_once("PersistenceDriver.php");

/**
 * Encapsulates a driver that persists unique user identifier into a crypted "remember me" cookie variable.
 */
class RememberMePersistenceDriver implements PersistenceDriver {
	private $token;
	
	private $parameterName;
	private $expirationTime;
	private $isHttpOnly;
	private $isSecure;
	
	/**
	 * Creates a persistence driver object.
	 * 
	 * @param string $secret Strong password to use for crypting. (Check: http://randomkeygen.com/)
	 * @param string $parameterName Name of SESSION parameter that holds cypted unique user identifier.
	 * @param number $expirationTime Time by which cookie expires (cannot be renewed), in seconds.
	 * @param string $isHttpOnly  Whether or not cookie should be using HTTP-only.
	 * @param string $isSecure Whether or not cookie should be using HTTPS-only.
	 */
	public function __construct($secret, $parameterName, $expirationTime, $isHttpOnly = false, $isSecure = false) {
		$this->token = new SynchronizerToken((isset($_SERVER["REMOTE_ADDR"])?$_SERVER["REMOTE_ADDR"]:""), $secret);		
		$this->parameterName = $parameterName;
		$this->expirationTime = $expirationTime;
		$this->isHttpOnly = $isHttpOnly;
		$this->isSecure = $isSecure;
	}

	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::load()
	 */
	public function load() {
		if(empty($_COOKIE[$this->parameterName])) {
			return;
		}
		
		try {
			return $this->token->decode($_COOKIE[$this->parameterName]);
		} catch(Exception $e) {
			// delete bad cookie
			setcookie ($this->parameterName, "", 1);
			setcookie ($this->parameterName, false);
			unset($_COOKIE[$this->parameterName]);
			// rethrow exception, unless it's token expired
			if($e instanceof TokenExpiredException) {
				return;
			} else {
				throw $e;
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::save()
	 */
	public function save($userID) {
		$token = $this->token->encode($userID, $this->expirationTime);
		setcookie($this->parameterName, $token, time()+$this->expirationTime, "", "", $this->isSecure, $this->isHttpOnly);
		$_COOKIE[$this->parameterName] = $token;
	}
	
	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::clear()
	 */
	public function clear($userID) {
		setcookie ($this->parameterName, "", 1);
		setcookie ($this->parameterName, false);
		unset($_COOKIE[$this->parameterName]);
	}
}