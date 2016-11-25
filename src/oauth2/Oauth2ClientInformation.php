<?php
class Oauth2ClientInformation {
    private $name;
    private $callbackURI;
    private $credentials;
   
    public function setName($name) {
        $this->name = $name;
    }
    
    public function getName() {
        return $this->name;
    }
    
    public function setCallbackURI($callbackURI) {
        $this->callbackURI = $callbackURI;
    }

    public function getCallbackURI() {
        return $this->callbackURI;
    }
    
    public function setCredentials(Oauth2ClientCredentials $credentials) {
        $this->credentials = $credentials;
    }
    
    public function getCredentials() {
        return $this->credentials;
    }
}