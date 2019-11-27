<?php
namespace Lucinda\WebSecurity\Authentication\OAuth2;


/**
 * Defines blueprints for a DAO that reflects oauth2 authentication results to database.
 */
interface AuthenticationDAO
{
    /**
     * Logs in OAuth2 user into current application. Exchanges authenticated OAuth2 user information for a local user ID.
     *
     * @param UserInformation $userInformation Object encapsulating detected OAuth2 user information.
     * @param string $accessToken Access token to be saved in further requests for above user.
     * @return mixed Unique user identifier (typically an integer)
     */
    public function login(UserInformation $userInformation, string $accessToken);
    
    /**
     * Logs out local user and removes saved access token
     *
     * @param mixed $userID Unique user identifier (typically an integer)
     */
    public function logout($userID): void;
}
