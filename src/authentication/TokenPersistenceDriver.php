<?php
require_once("PersistenceDriver.php");

/**
 * Encapsulates a driver that persists unique user identifier into a crypted token that's received from an Authorization header via TLS.
 */
class TokenPersistenceDriver implements PersistenceDriver {
	private $expirationTime;
	private $regenerationTime;
	
	private $tokenDriver;
	private $accessToken;

	/**
	 * Creates a persistence driver object.
	 *
	 * @param string $secret Strong password to use for crypting. (Check: http://randomkeygen.com/)
	 * @param number $expirationTime Time by which token expires (can be renewed), in seconds.
	 * @param string $regenerationTime Time by which token is renewed, in seconds.
	 */
	public function __construct($secret, $expirationTime = 3600, $regenerationTime = 60) {
		$this->tokenDriver = new SynchronizerToken((isset($_SERVER["REMOTE_ADDR"])?$_SERVER["REMOTE_ADDR"]:""), $secret);		
		$this->expirationTime = $expirationTime;
		$this->regenerationTime = $regenerationTime;
	}

	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::load()
	 */
	public function load() {
		if(!isset($_SERVER["HTTP_AUTHORIZATION"]) || strpos($_SERVER["HTTP_AUTHORIZATION"],"Token ")!==0) {
			return;
		}
		
		$token = substr($_SERVER["HTTP_AUTHORIZATION"],6);
		$userID = null;
		// decode token
		try {
			$userID = $this->tokenDriver->decode($token, $this->regenerationTime);
		} catch(TokenRegenerationException $e) {
			$userID = $e->getUserId();
			$this->accessToken = $this->tokenDriver->encode($userID, $this->expirationTime);
		} catch(TokenExpiredException $e) {
			$this->accessToken = null;
			return;
		}
		return $userID;
	}

	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::save()
	 */
	public function save($userID) {
		$this->accessToken = $this->tokenDriver->encode($userID, $this->expirationTime);
	}
	
	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::clear()
	 */
	public function clear($userID) {
		$this->accessToken = "";
	}
	
	/**
	 * Gets access token value.
	 * 
	 * @return string
	 */
	public function getAccessToken() {
		return $this->accessToken;
	}
}