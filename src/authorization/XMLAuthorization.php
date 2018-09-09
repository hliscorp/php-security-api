<?php
namespace Lucinda\WebSecurity;
require_once("AuthorizationResult.php");
require_once("AuthorizationException.php");

/**
 * Encapsulates request authorization via XML that must have routes configured as:
 * <routes>
 * 	<route url="{PAGE_TO_AUTHORIZE" access="ROLE_GUEST|ROLE_USER" ... />
 * 	...
 * </routes>
 */
class XMLAuthorization {
	const ROLE_GUEST = "GUEST";
	private $loggedInFailureCallback;
	private $loggedOutFailureCallback;
	
	/**
	 * Creates an object
	 *
	 * @param string $loggedInFailureCallback
	 * @param string $loggedOutFailureCallback
	 */
	public function __construct($loggedInFailureCallback, $loggedOutFailureCallback) {
		$this->loggedInFailureCallback = $loggedInFailureCallback;
		$this->loggedOutFailureCallback = $loggedOutFailureCallback;
	}
    
    /**
     * Performs an authorization task.
     * 
     * @param \SimpleXMLElement $xml
     * @param string $routeToAuthorize
     * @param integer $userID
     * @throws AuthorizationException If route is misconfigured.
     * @return AuthorizationResult
     */
    public function authorize(\SimpleXMLElement $xml, $routeToAuthorize, $userID = 0) {
        $status = 0;
        $callbackURI = "";
        
        // check if user is authenticated
        $isUserGuest = ($userID==0?true:false);
        
        // get user roles
        $userRoles = $this->getUserRoles($xml, $userID);
        
        // get page roles
        $pageRoles = $this->getPageRoles($xml, $routeToAuthorize);
        if(empty($pageRoles)) {
        	$status = AuthorizationResultStatus::NOT_FOUND;
        	$callbackURI = ($isUserGuest?$this->loggedOutFailureCallback:$this->loggedInFailureCallback);
        } else {
        	// compare user roles to page roles
        	$allowed = false;
        	foreach($pageRoles as $role) {
        		if(in_array($role, $userRoles)) {
        			$allowed= true;
        			break;
        		}
        	}
        	
        	// now perform rights check
        	if($allowed) {
        		$status = AuthorizationResultStatus::OK;
        	} else if($isUserGuest){
        		$status = AuthorizationResultStatus::UNAUTHORIZED;
        		$callbackURI = $this->loggedOutFailureCallback;
        	} else {
        		$status = AuthorizationResultStatus::FORBIDDEN;
        		$callbackURI = $this->loggedInFailureCallback;
        	}
        }
        
        return new AuthorizationResult($status,$callbackURI);
    }
    
    /**
     * Gets user roles from XML
     * 
     * @param \SimpleXMLElement $xml
     * @param integer $userID
     * @throws AuthorizationException
     * @return string[]
     */
    private function getUserRoles(\SimpleXMLElement $xml, $userID) {
    	$userRoles = array();
    	if($userID) {
    		$tmp = (array) $xml->users;
    		$tmp = $tmp["user"];
    		if(!is_array($tmp)) $tmp = array($tmp);
    		foreach($tmp as $info) {
    			$userIDTemp = (string) $info["id"];
    			$roles = (string) $info["roles"];
    			if(!$userIDTemp || !$roles) throw new AuthorizationException("XML tag users > user requires parameters: id, roles");
    			if($userIDTemp == $userID) {
    				$tmp = explode(",",$roles);
    				foreach($tmp as $role) {
    					$userRoles[] = trim($role);
    				}
    			}
    		}
    		if(empty($userRoles)) throw new AuthorizationException("User not found in XML!");
    	} else {
    		$userRoles[] = self::ROLE_GUEST;
    	}
    	return $userRoles;
    }
    
    
    /**
     * Gets page roles from XML
     *
     * @param \SimpleXMLElement $xml
     * @param integer $userID
     * @throws AuthorizationException
     * @return string[]
     */
    private function getPageRoles(\SimpleXMLElement $xml, $routeToAuthorize) {
    	$pageRoles = array();
    	$tmp = (array) $xml->routes;
    	$tmp = $tmp["route"];
    	if(!is_array($tmp)) $tmp = array($tmp);
    	foreach($tmp as $info) {
    		$path = (string) $info['url'];
    		if($path != $routeToAuthorize) continue;
    		
    		if(empty($info['roles'])) throw new AuthorizationException("XML tag routes > route requires parameter: roles");
    		$tmp = (string) $info["roles"];
    		$tmp= explode(",",$tmp);
    		foreach($tmp as $role) {
    			$pageRoles[] = trim($role);
    		}    		
    	}
    	return $pageRoles;
    }
}