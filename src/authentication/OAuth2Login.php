<?php
/**
 * Defines blueprints for login via OAuth2 provider.
 */
interface OAuth2Login {
	/**
	 * Gets remote user information from oauth2 driver via access token.
	 * 
	 * @param string $accessToken OAuth2 access token
	 * @return OAuth2UserInformation Remote user information
	 */
	function login($accessToken);
	
	/**
	 * Gets authorization code scopes required by login operation.
	 * 
	 * @return string[]
	 */
	function getDefaultScopes();
}