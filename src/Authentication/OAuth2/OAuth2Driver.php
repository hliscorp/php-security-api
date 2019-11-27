<?php
namespace Lucinda\WebSecurity;

/**
 * Defines driver to abstract OAuth2 operations required by Security API.
 */
interface OAuth2Driver
{
    /**
     * Gets remote user information from oauth2 driver via access token.
     *
     * @param string $accessToken OAuth2 access token
     * @return OAuth2UserInformation Remote user information
     */
    public function getUserInformation(string $accessToken): OAuth2UserInformation;
    
    /**
     * Gets authorization code scopes required by login operation.
     *
     * @return string[]
     */
    public function getDefaultScopes(): array;
}
