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
	 * Sets URL of access token endpoint @ Oauth2 Server
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
	 * Executes request and wraps response.
	 * 
	 * @param RequestExecutor $executor Performs request execution.
	 * @param ResponseWrapper $wrapper Performs wrapping of response. 
	 * @throws ClientException
	 */
	public function execute(RequestExecutor $executor, ResponseWrapper $wrapper) {
		if(!$this->clientID) throw new ClientException("Client ID is required for access token requests!");
		if(!$this->code) throw new ClientException("Authorization code is required for access token requests!");
		$parameters = array();
		$parameters["grant_type"] = "authorization_code";
		$parameters["client_id"] = $this->clientID;
		$parameters["code"] = $this->code;
		if($this->redirectURL) {
			$parameters["redirect_uri"] = $this->redirectURL;
		}
		$wrapper->wrap($executor->execute($this->endpointURL, $parameters));
	}
}