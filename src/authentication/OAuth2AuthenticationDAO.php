<?php
/**
 * Defines blueprints for a DAO that reflects oauth2 authentication results to database.
 */
interface OAuth2AuthenticationDAO {
	/**
	 * Logs in OAuth2 user into current application. Exchanges authenticated OAuth2 user information for a local user ID.
	 * 
	 * @param UserInformation $userInformation Object encapsulating detected OAuth2 user information.
	 * @param string $accessToken Access token to be saved in further requests for above user.
	 * @param string $createIfNotExists Toggles whether or not user will be automatically added to DB if not found.
	 * @return mixed Unique user identifier (typically an integer)
	 */
    function login(OAuth2UserInformation $userInformation, $accessToken, $createIfNotExists=true);
    
    /**
     * Logs out local user and removes saved access token
     * 
     * @param mixed $userID Unique user identifier (typically an integer)
     */
    function logout($userID);
    
    /**
     * Gets access token for logged in local user.
     * 
     * @param mixed $userID Unique user identifier (typically an integer)
     * @return string
     */
    function getAccessToken($userID);
}