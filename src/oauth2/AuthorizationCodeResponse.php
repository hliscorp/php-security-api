<?php
namespace OAuth2;

/**
 * Encapsulates a successful authorization code response according to RFC6749
 */
class AuthorizationCodeResponse {
	protected $code;
	protected $state;


	/**
	 * Sets authorization code.
	 *
	 * @param string $code
	 */
	public function setCode($code) {
		$this->code = $code;
	}
	
	/**
	 * Gets authorization code.
	 * 
	 * @return string
	 */
	public function getCode() {
		return $this->code;
	}
	
	/**
	 * Sets opaque value used by the client to maintain state between the request and callback
	 *
	 * @param string $scope
	 */
	public function setState($state) {
		$this->state = $state;
	}
	
	/**
	 * Gets opaque value used by the client to maintain state between the request and callback
	 */
	public function getState() {
		return $this->state;
	}
}