<?php
namespace Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Binds RememberMePersistenceDriver @ SECURITY API with settings from configuration.xml @ SERVLETS-API and sets up an object on which one can
 * forward remember-me cookie operations.
 */
class RememberMeWrapper extends PersistenceDriverWrapper
{
    const DEFAULT_PARAMETER_NAME = "uid";
    const DEFAULT_EXPIRATION_TIME = 24*3600;
    
    /**
     * Sets up current persistence driver from XML into driver property.
     *
     * @param \SimpleXMLElement $xml Contents of XML tag that sets up persistence driver.
     * @param string $ipAddress Detected client IP address
     * @throws ConfigurationException If resources referenced in XML do not exist or do not extend/implement required blueprint.
     */
    protected function setDriver(\SimpleXMLElement $xml, $ipAddress): void
    {
        $secret = (string) $xml["secret"];
        if (!$secret) {
            throw new ConfigurationException("Attribute 'secret' is mandatory for 'remember_me' tag");
        }

        $parameterName = (string) $xml["parameter_name"];
        if (!$parameterName) {
            $parameterName = self::DEFAULT_PARAMETER_NAME;
        }

        $expirationTime = (integer) $xml["expiration"];
        if (!$expirationTime) {
            $expirationTime = self::DEFAULT_EXPIRATION_TIME;
        }

        $isHttpOnly = (integer) $xml["is_http_only"];
        $isHttpsOnly = (integer) $xml["is_https_only"];
        
        $this->driver = new RememberMePersistenceDriver($secret, $parameterName, $expirationTime, $isHttpOnly, $isHttpsOnly, $ipAddress);
    }
}
