<?php
/**
 * Defines blueprints for login via OAuth2 provider.
 */
interface OAuth2Login {
	/**
	 * Gets link to OAuth2 provider authorization code endpoint.
	 * 
	 * @return string URL to authorization code endpoint
	 */
	function getAuthorizationEndpoint();
	
	/**
	 * Retrieves access token via authorization code then gets remote user information.
	 * 
	 * @param string $authorizationCode OAuth2 authorization code
	 * @return OAuth2UserInformation Remote user information
	 */
	function login($authorizationCode);
	
	/**
	 * Gets access token created during login operation.
	 * 
	 * @return string
	 */
	function getAccessToken();
}