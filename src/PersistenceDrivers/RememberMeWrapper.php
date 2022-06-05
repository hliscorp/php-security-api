<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Binds RememberMePersistenceDriver @ SECURITY API with settings from configuration.xml @ SERVLETS-API and
 * sets up an object on which one can forward remember-me cookie operations.
 */
class RememberMeWrapper extends PersistenceDriverWrapper
{
    public const DEFAULT_PARAMETER_NAME = "uid";
    public const DEFAULT_EXPIRATION_TIME = 24*3600;

    /**
     * Sets up current persistence driver from XML into driver property.
     *
     * @param  \SimpleXMLElement $xml       Contents of XML tag that sets up persistence driver.
     * @param  string            $ipAddress Detected client IP address
     * @throws ConfigurationException If resources referenced in XML do not exist or do not extend/implement blueprint.
     */
    protected function setDriver(\SimpleXMLElement $xml, string $ipAddress): void
    {
        $secret = (string) $xml["secret"];
        if (!$secret) {
            throw new ConfigurationException("Attribute 'secret' is mandatory for 'remember_me' tag");
        }

        $parameterName = (string) $xml["parameter_name"];
        if (!$parameterName) {
            $parameterName = self::DEFAULT_PARAMETER_NAME;
        }

        $securityOptions = new CookieSecurityOptions();
        $expirationTime = (int) $xml["expiration"];
        $securityOptions->setExpirationTime($expirationTime ? $expirationTime : self::DEFAULT_EXPIRATION_TIME);
        $securityOptions->setIsHttpOnly((bool)((int)$xml["is_http_only"]));
        $securityOptions->setIsSecure((bool)((int)$xml["is_https_only"]));

        $this->driver = new RememberMePersistenceDriver(
            $secret,
            $parameterName,
            $securityOptions,
            $ipAddress
        );
    }
}
