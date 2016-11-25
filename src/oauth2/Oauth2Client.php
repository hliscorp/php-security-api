<?php
abstract class Oauth2Client {
    private $clientInformation;
    private $serverInformation;
    
    public function __construct(Oauth2ServerInformation $serverInformation, Oauth2ClientInformation $clientInformation) {
        $this->clientInformation = $clientInformation;
        $this->serverInformation = $serverInformation;
    }
    
    /**
     * Requests an authorization code to be received via redirect uri callback.
     * 
     * @param string $scope Scope of access request.  The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings.
     * @param string $redirect_uri Callback authorization code will be sent to. If not supplied, application link will be used automatically.
     * @param string $state An opaque value used by the client to maintain state between the request and callback.
     * @return string Link to authorization API.
     */
    public function getAuthorizationCode($scope="", $redirect_uri="", $state=""){
        return  $this->serverInformation->getAuthorizationCodeEnpointURL()
        ."?client_id=".$this->clientInformation->getCredentials()->getClientID()
        .($redirect_uri?"&redirect_uri=".$redirect_uri:"")
        .($scope?"&scope=".$scope:"")
        ."&response_type=code";
    }
       
    public function parseError($error, $error_description, $error_uri, $state="") {
        $exception = new Oauth2Exception($error_description, $error);
        $exception->setErrorURI($error_uri);
        $exception->setState($state);
        throw $exception;
    }
    
    /**
     * Requests an access token by authorization code to be received via redirect uri callback.
     * 
     * @param string $authorizationCode Oauth2 authorization code. 
     * @param string $redirect_uri  Callback authorization code will be sent to. Required if it was included in authorization request.
     * @return string
     */
    public function getAccessToken($authorizationCode, $redirect_uri="") {
        return  $this->serverInformation->getTokenEndpointURL()
        ."?client_id=".$this->clientInformation->getCredentials()->getClientID()
        ."&client_secret=".$this->clientInformation->getCredentials()->getClientSecret()
        ."&grant_type=authorization_code"
        ."&code=".$authorizationCode
        .($redirect_uri?"&redirect_uri=".$redirect_uri:"");
    }
    
    abstract public function parseAuthorizationCodeResponse($access_token, $token_type, $expires_in, $scope="", $state="");
}