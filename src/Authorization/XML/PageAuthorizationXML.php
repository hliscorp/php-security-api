<?php
namespace Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\Authorization\Exception;

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
     * Gets page roles from XML
     *
     * @param string $routeToAuthorize
     * @throws Exception
     * @return string[]
     */
    public function getRoles(string $routeToAuthorize): array
    {
        $pageRoles = array();
        $tmp = (array) $this->xml->routes;
        $tmp = $tmp["route"];
        if (!is_array($tmp)) {
            $tmp = array($tmp);
        }
        foreach ($tmp as $info) {
            $path = (string) $info['url'];
            if ($path != $routeToAuthorize) {
                continue;
            }
            
            if (empty($info['roles'])) {
                throw new Exception("XML tag routes > route requires parameter: roles");
            }
            $tmp = (string) $info["roles"];
            $tmp= explode(",", $tmp);
            foreach ($tmp as $role) {
                $pageRoles[] = trim($role);
            }
        }
        return $pageRoles;
    }
}
