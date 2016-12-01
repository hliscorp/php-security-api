<?php
namespace OAuth2;

/**
 * Encapsulates a successful access token response according to RFC6749
 */
class AccessTokenResponse {
	protected $accessToken;
	protected $tokenType;
	protected $expiresIn;
	protected $refreshToken;
	protected $scope;
	
	/**
	 * Sets access token issued by the authorization server.
	 * 
	 * @param string $accessToken
	 */
	public function setAccessToken($accessToken) {
		$this->accessToken = $accessToken;
	}
	
	/**
	 * Gets access token issued by the authorization server.
	 * 
	 * @return string
	 */
	public function getAccessToken() {
		return $this->accessToken;
	}

	/**
	 * Sets token type received by the authorization server to use for protected resource request.
	 *
	 * @param string $tokenType
	 */
	public function setTokenType($tokenType) {
		$this->tokenType = $tokenType;
	}
	
	/**
	 * Gets token type received by the authorization server to use for protected resource request.
	 * 
	 * @return string
	 */
	public function getTokenType() {
		return $this->tokenType;
	}

	/**
	 * Sets access token lifetime (in seconds) issued by the authorization server.
	 *
	 * @param string $expiresIn
	 */
	public function setExpiresIn($expiresIn) {
		$this->expiresIn = $expiresIn;
	}
	
	/**
	 * Gets access token lifetime (in seconds) issued by the authorization server.
	 * 
	 * @return string
	 */
	public function getExpiresIn() {
		return $this->expiresIn;
	}

	/**
	 * Sets refresh token used to obtain new access tokens using the same authorization grant
	 *
	 * @param string $refreshToken
	 */
	public function setRefreshToken($refreshToken) {
		$this->refreshToken = $refreshToken;
	}
	
	/**
	 * Gets refresh token used to obtain new access tokens using the same authorization grant
	 * 
	 * @return string
	 */
	public function getRefreshToken() {
		return $this->refreshToken;
	}

	/**
	 * Sets scope of token issued by the authorization server.
	 *
	 * @param string $scope
	 */
	public function setScope($scope) {
		$this->scope = $scope;
	}
	
	/**
	 * Gets scope of token issued by the authorization server.
	 * 
	 * @return string
	 */
	public function getScope() {
		return $this->scope;
	}
}