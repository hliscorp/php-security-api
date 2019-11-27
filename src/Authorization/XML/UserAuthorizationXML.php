<?php
namespace Lucinda\WebSecurity;

require_once("UserAuthorizationRoles.php");

/**
 * Encapsulates users authorization via <users> XML tag
 */
class UserAuthorizationXML implements UserAuthorizationRoles
{
    const ROLE_GUEST = "GUEST";
    
    private $xml;
    
    /**
     * Sets XML to authorize into
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml): void
    {
        $this->xml = $xml;
    }
    
    /**
     * Gets user roles from XML
     *
     * @param integer $userID
     * @throws AuthorizationException
     * @return string[]
     */
    public function getRoles(int $userID): array
    {
        $userRoles = array();
        if ($userID) {
            $tmp = (array) $this->xml->users;
            $tmp = $tmp["user"];
            if (!is_array($tmp)) {
                $tmp = array($tmp);
            }
            foreach ($tmp as $info) {
                $userIDTemp = (string) $info["id"];
                $roles = (string) $info["roles"];
                if (!$userIDTemp || !$roles) {
                    throw new AuthorizationException("XML tag users > user requires parameters: id, roles");
                }
                if ($userIDTemp == $userID) {
                    $tmp = explode(",", $roles);
                    foreach ($tmp as $role) {
                        $userRoles[] = trim($role);
                    }
                }
            }
            if (empty($userRoles)) {
                throw new AuthorizationException("User not found in XML!");
            }
        } else {
            $userRoles[] = self::ROLE_GUEST;
        }
        return $userRoles;
    }
}
