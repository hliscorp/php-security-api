<?php
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
     * @param SimpleXMLElement $xml
     * @param string $routeToAuthorize
     * @param string[] $userRoles
     * @throws ApplicationException If route is misconfigured.
     * @return AuthorizationResult
     */
    public function authorize(SimpleXMLElement $xml, $routeToAuthorize, $userRoles) {
        $status = 0;
        $callbackURI = "";
        
        // check if user is authenticated
        $isUserGuest = (sizeof($userRoles)==1 && $userRoles[0]==self::ROLE_GUEST);

    	// check rights 
    	$tmp = (array) $xml->routes;
    	$tmp = $tmp["route"];
    	if(!is_array($tmp)) $tmp = array($tmp);
    	foreach($tmp as $info) {
    		$path = (string) $info['url'];
    		if($path != $routeToAuthorize) continue;
    		
    		// check if page roles match with user roles
    		if(empty($info['roles'])) throw new AuthorizationException("XML tag roles not set for route!");
    		$tmp = (string) $info["roles"];
    		$pageRoles = explode(",",$tmp);
    		$found = false;
    		foreach($pageRoles as $role) {
    			if(in_array(trim($role), $userRoles)) {
    				$found = true;
    				break;
    			}
    		}
    		
    		// now perform rights check
    		if($found) {
    			$status = AuthorizationResultStatus::OK;
    		} else if($isUserGuest){
    			$status = AuthorizationResultStatus::UNAUTHORIZED;
    			$callbackURI = $this->loggedOutFailureCallback;
    		} else {
    			$status = AuthorizationResultStatus::FORBIDDEN;
    			$callbackURI = $this->loggedInFailureCallback;
    		}
    	}
    	if($status==0) {
    		$status = AuthorizationResultStatus::NOT_FOUND;
    		$callbackURI = ($isUserGuest?$this->loggedOutFailureCallback:$this->loggedInFailureCallback);
    	}
        return new AuthorizationResult($status,$callbackURI);
    }
}