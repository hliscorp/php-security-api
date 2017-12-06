<?php
require_once("TokenPersistenceDriver.php");

/**
 * Encapsulates a PersistenceDriver that employs SynchronizerToken to authenticate users.
 */
class SynchronizerTokenPersistenceDriver extends TokenPersistenceDriver {
	private $expirationTime;
	private $regenerationTime;
	private $tokenDriver;
	
	/**
	 * Creates a persistence driver object.
	 *
	 * @param string $secret Strong password to use for crypting. (Check: http://randomkeygen.com/)
	 * @param number $expirationTime Time by which token expires (can be renewed), in seconds.
	 * @param string $regenerationTime Time by which token is renewed, in seconds.
	 * @param string $ip Value of REMOTE_ADDR attribute, unless ignored.
	 */
	public function __construct($secret, $expirationTime = 3600, $regenerationTime = 60, $ip="") {
		$this->tokenDriver = new SynchronizerToken($ip, $secret);
		$this->expirationTime = $expirationTime;
		$this->regenerationTime = $regenerationTime;
	}
	
	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::load()
	 */
	public function load() {
		$this->setAccessToken();
		if(!$this->accessToken) return;
		$userID = null;
		// decode token
		try {
			$userID = $this->tokenDriver->decode($this->accessToken, $this->regenerationTime);
		} catch(TokenRegenerationException $e) {
			$userID = $e->getPayload();
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
	public function clear() {
		$this->accessToken = "";
	}
}