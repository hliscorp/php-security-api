<?php
namespace OAuth2;

/**
 * Encapsulates an access token request according to RFC6749
 */
class AccessTokenRequest {
	protected $endpointURL;
	protected $clientID;
	protected $redirectURL;
	protected $code;
	
	/**
	 * Location URL of access token endpoint @ Oauth2 Server
	 * 
	 * @param string $endpointURL
	 */
	public function __construct($endpointURL) {
		$this->endpointURL = $endpointURL;
	}
	
	/**
	 * Sets authorization code
	 * 
	 * @param string $code
	 */
	public function setCode($code) {
		$this->code = $code;
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
	 * Sets callback redirect URL to send access token to.
	 * 
	 * @param string $clientID
	 */
	public function setRedirectURL($redirectURL) {
		$this->redirectURL = $redirectURL;
	}
	
	/**
	 * Constructs request and redirects to endpoint.
	 * 
	 * @throws ClientException
	 */
	public function execute() {
		if(!$this->clientID) throw new ClientException("Setting client ID is required for authorization code requests!");
		if(!$this->code) throw new ClientException("Authorization code is required for access token requests!");
		$url = $this->endpointURL."?grant_type=authorization_code"
			."&client_id=".$this->clientID
			."&code=".$this->code
        	.($this->redirectURL?"&redirect_uri=".$this->redirectURL:"");
		header("Location: ".$url);
		exit();
	}
	
}