<?php
namespace OAuth2;

/**
 * Encapsulates an authorization code request according to RFC6749
 */
class AuthorizationCodeRequest {
	protected $endpointURL;
	protected $clientID;
	protected $redirectURL;
	protected $scope;
	protected $state;
	
	/**
	 * Location URL of authorization code endpoint @ Oauth2 Server
	 * @param unknown $endpointURL
	 */
	public function __construct($endpointURL) {
		$this->endpointURL = $endpointURL;
	}
	
	/**
	 * Sets unique client identifier.
	 * 
	 * @param string $clientID
	 */
	public function setClientID($clientID) {
		$this->clientID = $clientID;
	}
	
	/**
	 * Sets callback redirect URL to send code to.
	 * 
	 * @param string $clientID
	 */
	public function setRedirectURL($redirectURL) {
		$this->redirectURL = $redirectURL;
	}
	
	/**
	 * Sets scope of access request.
	 * 
	 * @param string $scope
	 */
	public function setScope($scope) {
		$this->scope = $scope;
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
	 * Constructs request and redirects to endpoint.
	 * 
	 * @throws ClientException
	 */
	public function execute() {
		if(!$this->clientID) throw new ClientException("Setting client ID is required for authorization code requests!");
		$url = $this->endpointURL."?response_type=code".
			"&client_id=".$this->clientID
        	.($this->redirectURL?"&redirect_uri=".$this->redirectURL:"")
        	.($this->scope?"&scope=".$this->scope:"")
        	.($this->state?"&redirect_uri=".$this->state:"");
		header("Location: ".$url);
		exit();
	}
}