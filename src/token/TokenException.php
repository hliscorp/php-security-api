<?php
/**
 * Exception thrown when token fails validation.
 */
class TokenException extends AuthenticationException{}

/**
 * Exception thrown when token needs to be refreshed.
 */
class TokenRegenerationException extends Exception {
	private $userID;
	
	public function setUserId($userID) {
		$this->userID = $userID;
	}
	
	public function getUserId() {
		return $this->userID;
	}
}

/**
 * Exception thrown when token expires.
 */
class TokenExpiredException extends Exception {}