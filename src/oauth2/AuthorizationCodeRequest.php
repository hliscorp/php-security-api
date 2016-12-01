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
	 * Executes request and wraps response.
	 * 
	 * @param RequestExecutor $executor Performs request execution.
	 * @param ResponseWrapper $wrapper Performs wrapping of response. 
	 * @throws ClientException
	 */
	public function execute(RequestExecutor $executor, ResponseWrapper $wrapper) {
		if(!$this->clientID) throw new ClientException("Setting client ID is required for authorization code requests!");
		$parameters = array();
		$parameters["response_type"] = "code";
		$parameters["client_id"] = $this->clientID;
		if($this->redirectURL) 	$parameters["redirect_uri"] = $this->redirectURL;
		if($this->scope) 		$parameters["scope"] = $this->scope;
		if($this->state) 		$parameters["state"] = $this->state;
		$wrapper->wrap($executor->execute($this->endpointURL, $parameters));
	}
}