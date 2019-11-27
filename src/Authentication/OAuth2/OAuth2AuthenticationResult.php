<?php
namespace Lucinda\WebSecurity;

require_once("AuthenticationResult.php");

/**
 * Encapsulates authentication response via oauth2 driver
 */
class OAuth2AuthenticationResult extends AuthenticationResult
{
    private $token;
    
    /**
     * Sets access token.
     *
     * @param string $token
     */
    public function setAccessToken(string $token): void
    {
        $this->token = $token;
    }
    
    /**
     * Gets access token
     *
     * @return string
     */
    public function getAccessToken(): string
    {
        return $this->token;
    }
}
