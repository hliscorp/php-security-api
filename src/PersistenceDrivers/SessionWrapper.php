<?php
namespace Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver as SessionPersistenceDriver;
use Lucinda\WebSecurity\ClassFinder;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Binds SessionPersistenceDriver @ SECURITY API with settings from configuration.xml @ SERVLETS-API and sets up an object on which one can
 * forward session persistence operations.
 */
class SessionWrapper extends PersistenceDriverWrapper
{
    const DEFAULT_PARAMETER_NAME = "uid";
    
    /**
     * Sets up current persistence driver from XML into driver property.
     *
     * @param \SimpleXMLElement $xml Contents of XML tag that sets up persistence driver.
     * @param string $ipAddress Detected client IP address
     * @throws ConfigurationException If resources referenced in XML do not exist or do not extend/implement required blueprint.
     */
    protected function setDriver(\SimpleXMLElement $xml, string $ipAddress): void
    {
        $parameterName = (string) $xml["parameter_name"];
        if (!$parameterName) {
            $parameterName = self::DEFAULT_PARAMETER_NAME;
        }

        $expirationTime = (integer) $xml["expiration"];
        $isHttpOnly = (integer) $xml["is_http_only"];
        $isHttpsOnly = (integer) $xml["is_https_only"];
        
        $handler = (string) $xml["handler"];
        if ($handler) {
            session_set_save_handler($this->getHandlerInstance($handler), true);
        }
        
        $this->driver = new SessionPersistenceDriver($parameterName, $expirationTime, $isHttpOnly, $isHttpsOnly, $ipAddress);
    }
    
    /**
     * Gets instance of handler based on handler name
     *
     * @param string $handlerClass Name of handler class
     * @throws ConfigurationException If resources referenced in XML do not exist or do not extend/implement required blueprint.
     * @return \SessionHandlerInterface
     */
    private function getHandlerInstance(string $handlerClass): \SessionHandlerInterface
    {
        $classFinder = new ClassFinder("");
        $handlerClass = $classFinder->find($handlerClass);
        $object = new $handlerClass();
        if (!($object instanceof \SessionHandlerInterface)) {
            throw new ConfigurationException("Handler must be instance of SessionHandlerInterface!");
        }
        return $object;
    }
}
