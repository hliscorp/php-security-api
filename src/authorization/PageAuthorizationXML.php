<?php
namespace Lucinda\WebSecurity;

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
     * @param \SimpleXMLElement $xml
     * @param integer $userID
     * @throws AuthorizationException
     * @return string[]
     */
    public function getRoles($routeToAuthorize)
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
                throw new AuthorizationException("XML tag routes > route requires parameter: roles");
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
