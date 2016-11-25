<?php
interface Oauth2ServerInformation {
    public function getAuthorizationCodeEnpointURL();
    public function getTokenEndpointURL();
    public function getApiURL();
}