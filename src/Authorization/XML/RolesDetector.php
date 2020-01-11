<?php
namespace Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\ConfigurationException;

/**
 * Detects roles from matching child tag or, if not found, gets default roles
 */
class RolesDetector
{
    private $roles;
    
    /**
     * Calls for roles detection
     * 
     * @param \SimpleXMLElement $xml
     * @param string $parentTag
     * @param string $childTag
     * @param string $requiredAttribute
     * @param mixed $matchingValue
     */
    public function __construct(\SimpleXMLElement $xml, string $parentTag, string $childTag, string $requiredAttribute, $matchingValue)
    {
        $this->setRoles($xml, $parentTag, $childTag, $requiredAttribute, $matchingValue);
    }
    
    /**
     * etects roles from matching child tag or, if not found, gets default roles
     *
     * @param \SimpleXMLElement $xml
     * @param string $parentTag
     * @param string $childTag
     * @param string $requiredAttribute
     * @param mixed $matchingValue
     */
    private function setRoles(\SimpleXMLElement $xml, string $parentTag, string $childTag, string $requiredAttribute, $matchingValue): void
    {
        $roles = [];
        
        // get default roles
        $children = $xml->{$parentTag};
        
        // override with child-specific roles, if existing
        $tmp = (array) $children;
        $tmp = $tmp[$childTag];
        if (!is_array($tmp)) {
            $tmp = array($tmp);
        }
        foreach ($tmp as $info) {
            $value = (string) $info[$requiredAttribute];
            if (!$value) {
                throw new ConfigurationException("XML tag ".$parentTag." > ".$childTag." requires attribute: ".$requiredAttribute);
            }
            if ($value == $matchingValue) {
                $roles = $this->parseRoles($info, $parentTag, $childTag);
                break;
            }
        }
        $this->roles = $roles;
    }
    
    /**
     * Parses a tag for roles
     *
     * @param \SimpleXMLElement $info
     * @param string $parentTag
     * @param string $childTag
     * @throws ConfigurationException
     * @return string[]
     */
    private function parseRoles(\SimpleXMLElement $info, string $parentTag, string $childTag): array
    {
        $pageRoles = [];
        if (empty($info['roles'])) {
            throw new ConfigurationException("XML tag ".$parentTag." > ".$childTag." requires attribute: roles");
        }
        $tmp = (string) $info["roles"];
        $tmp= explode(",", $tmp);
        foreach ($tmp as $role) {
            $pageRoles[] = trim($role);
        }
        return $pageRoles;
    }
    
    /**
     * Gets roles detected
     * 
     * @return string[]
     */
    public function getRoles(): array
    {
        return $this->roles;
    }
}

