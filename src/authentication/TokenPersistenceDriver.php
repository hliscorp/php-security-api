<?php
require_once("../token/SynchronizerToken.php");

/**
 * Encapsulates a driver that persists unique user identifier into a crypted token that's received from an Authorization header via TLS.
 */
class TokenPersistenceDriver implements PersistenceDriver {
	private $expirationTime;
	private $regenerationTime;
	
	private $token;

	/**
	 * Creates a persistence driver object.
	 *
	 * @param string $secret Strong password to use for crypting. (Check: http://randomkeygen.com/)
	 * @param number $expirationTime Time by which token expires (can be renewed), in seconds.
	 * @param string $regenerationTime Time by which token is renewed, in seconds.
	 */
	public function __construct($secret, $expirationTime = 3600, $regenerationTime = 60) {
		$this->token = new SynchronizerToken((isset($_SERVER["REMOTE_ADDR"])?$_SERVER["REMOTE_ADDR"]:""), $secret);		
		$this->expirationTime = $expirationTime;
		$this->regenerationTime = $regenerationTime;
	}

	/**
	 * Loads logged in user's unique identifier from driver.
	 *
	 * @return mixed Unique user identifier (usually an integer) or NULL if none exists.
	 * @throws TokenException If token has expired or was issued from a different IP.
	 * @throws EncryptionException If cookie value could not be decrypted.
	 */
	public function load() {
		if(!isset($_SERVER["HTTP_AUTHORIZATION"]) || strpos($_SERVER["HTTP_AUTHORIZATION"],"Token ")!==0) {
			return;
		}
		
		$token = substr($_SERVER["HTTP_AUTHORIZATION"],6);
		$userID = null;
		// decode token
		try {
			$userID = $this->token->decode($token, $this->regenerationTime);
		} catch(TokenRegenerationException $e) {
			// regenerate token
			$userID = $e->getUserId();
			$this->token = $this->token->encode($userID, $this->expirationTime);
		}
		return $userID;
	}

	/**
	 * Saves user's unique identifier into driver (eg: on login).
	 *
	 * @param mixed $userID Unique user identifier (usually an integer)
	 * @throws EncryptionException If cookie could not be encrypted
	 */
	public function save($userID) {
		$this->token = $this->token->encode($userID, $this->expirationTime);
	}
	
	/**
	 * {@inheritDoc}
	 * @see PersistenceDriver::clear()
	 */
	public function clear($userID) {
		$this->token = "";
	}
	
	/**
	 * Gets token value.
	 * 
	 * @return string
	 */
	public function getToken() {
		return $this->token;
	}
}