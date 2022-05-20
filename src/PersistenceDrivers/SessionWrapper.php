<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver as SessionPersistenceDriver;

/**
 * Binds SessionPersistenceDriver @ SECURITY API with settings from configuration.xml @ SERVLETS-API and sets up
 * an object on which one can forward session persistence operations.
 */
class SessionWrapper extends PersistenceDriverWrapper
{
    public const DEFAULT_PARAMETER_NAME = "uid";

    /**
     * Sets up current persistence driver from XML into driver property.
     *
     * @param \SimpleXMLElement $xml Contents of XML tag that sets up persistence driver.
     * @param string $ipAddress Detected client IP address
     */
    protected function setDriver(\SimpleXMLElement $xml, string $ipAddress): void
    {
        $parameterName = (string) $xml["parameter_name"];
        if (!$parameterName) {
            $parameterName = self::DEFAULT_PARAMETER_NAME;
        }

        $securityOptions = new CookieSecurityOptions();
        $securityOptions->setExpirationTime((int) $xml["expiration"]);
        $securityOptions->setIsHttpOnly((bool)((int)$xml["is_http_only"]));
        $securityOptions->setIsSecure((bool)((int)$xml["is_https_only"]));

        $handler = (string) $xml["handler"];
        if ($handler) {
            session_set_save_handler(new $handler(), true);
        }

        $this->driver = new SessionPersistenceDriver(
            $parameterName,
            $securityOptions,
            $ipAddress
        );
    }
}
