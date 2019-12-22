<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\Token;

/**
 * Encapsulates a driver that persists unique user identifier into a crypted self-regenerating token that
 * must be sent by clients via Authorization header of bearer type.
 */
abstract class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    protected $accessToken;
    
    /**
     * Sets access token value based on contents of HTTP authorization header of "bearer" type
     */
    public function setAccessToken(): void
    {
        $headers = getallheaders();
        if (!isset($headers["Authorization"]) || stripos($headers["Authorization"], "Bearer ")!==0) {
            return;
        }
        
        $this->accessToken = trim(substr($headers["Authorization"], 7));
    }
    
    /**
     * Gets access token value.
     *
     * @return string
     */
    public function getAccessToken(): string
    {
        return $this->accessToken;
    }
}
