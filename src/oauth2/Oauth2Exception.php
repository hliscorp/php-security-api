<?php

class Oauth2Exception extends Exception {
    private $uri;
    private $state;

    public function setDescription($description) {
        $this->message = $description;
    }
    
    public function getDescription() {
        
    }

    public function setURI($uri) {
        $this->uri = $uri;
    }

    public function getURI() {
        return $this->errorURI;
    }

    public function setState($state) {
        $this->state = $state;
    }

    public function getState() {
        return $this->state;
    }
}