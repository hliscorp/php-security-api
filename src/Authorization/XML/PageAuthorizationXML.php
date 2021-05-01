<?php
namespace Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\ConfigurationException;

/**
 * Encapsulates route authorization via <routes> XML tag
 */
class PageAuthorizationXML
{
    private $xml;
    
    /**
     * Sets XML to authorize into
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->xml = $xml;
    }
    
    /**
     * Gets roles from XML
     *
     * @param string $routeToAuthorize
     * @throws ConfigurationException
     * @return string[]
     */
    public function getRoles(string $routeToAuthorize): array
    {
        $detector = new RolesDetector($this->xml, "routes", "route", "id", $routeToAuthorize);
        return $detector->getRoles();
    }
}
