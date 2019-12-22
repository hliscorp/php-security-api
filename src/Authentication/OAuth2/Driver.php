<?php
namespace Lucinda\WebSecurity\Authentication\OAuth2;

/**
 * Defines driver to abstract OAuth2 operations required by Security API.
 */
interface Driver
{
    /**
     * Gets remote user information from oauth2 driver via access token.
     *
     * @param string $accessToken OAuth2 access token
     * @return UserInformation Remote user information
     */
    public function getUserInformation(string $accessToken): UserInformation;
    
    /**
     * Gets authorization code scopes required by login operation.
     *
     * @return string[]
     */
    public function getDefaultScopes(): array;
}
