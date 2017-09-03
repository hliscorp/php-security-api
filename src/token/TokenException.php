<?php
/**
 * Exception thrown when token fails validation.
 */
class TokenException extends Exception {}

/**
 * Exception thrown when token needs to be refreshed.
 */
class TokenRegenerationException extends Exception {
	private $payload;
	
	/**
	 * Sets payload to use in regeneration.
	 * 
	 * @param mixed $payload
	 */
	public function setPayload($payload) {
		$this->payload= $payload;
	}
	
	/**
	 * Gets payload that was used in regeneration.
	 * 
	 * @return mixed
	 */
	public function getPayload() {
		return $this->payload;
	}
}

/**
 * Exception thrown when token expires.
 */
class TokenExpiredException extends Exception {}