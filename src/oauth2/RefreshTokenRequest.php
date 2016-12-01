<?php
namespace OAuth2;

class RefreshTokenRequest {
	protected $endpointURL;
	protected $refreshToken;
	protected $scope;
	
	/**
	 * Location URL of refresh token endpoint @ Oauth2 Server
	 *
	 * @param string $endpointURL
	 */
	public function __construct($endpointURL) {
		$this->endpointURL = $endpointURL;
	}

	/**
	 * Sets refresh token originally issued to the client.
	 *
	 * @param string $refreshToken
	 */
	public function setRefreshToken($refreshToken) {
		$this->refreshToken = $refreshToken;
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
	 * Constructs request and redirects to endpoint.
	 * 
	 * @throws ClientException
	 */
	public function execute() {
		if(!$this->refreshToken) throw new ClientException("Refresh token is required for refresh token requests!");
		$url = $this->endpointURL."?grant_type=refresh_token"
			."&refreshToken=".$this->refreshToken
        	.($this->scope?"&scope=".$this->scope:"");
		header("Location: ".$url);
		exit();
	}
}