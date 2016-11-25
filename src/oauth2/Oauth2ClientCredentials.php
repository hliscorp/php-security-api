<?php
class Oauth2ClientCredentials {
    private $clientID;
    private $clientSecret;

    public function setClientID($clientID) {
        $this->clientID = $clientID;
    }
    
    public function getClientID() {
        return $this->clientID;
    }
    
    public function setClientSecret($clientSecret) {
        $this->clientSecret = $clientSecret;
    }
    
    public function getClientSecret() {
        return $this->clientSecret;
    }
}