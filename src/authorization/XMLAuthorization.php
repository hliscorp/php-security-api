<?php
namespace Lucinda\WebSecurity;
require_once("AuthorizationResult.php");
require_once("AuthorizationException.php");
require_once("PageAuthorizationXML.php");
require_once("UserAuthorizationXML.php");

/**
 * Encapsulates request authorization via XML that must have routes configured as:
 * <routes>
 * 	<route url="{PAGE_TO_AUTHORIZE" access="ROLE_GUEST|ROLE_USER" ... />
 * 	...
 * </routes>
 */
class XMLAuthorization {
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
     * @param UserAuthorizationRoles $userAuthorizationRoles
     * @throws AuthorizationException If route is misconfigured.
     * @return AuthorizationResult
     */
    public function authorize(\SimpleXMLElement $xml, $routeToAuthorize, $userID=0, UserAuthorizationRoles $userAuthorizationRoles) {
        $status = 0;
        $callbackURI = "";
        
        // check if user is authenticated
        $isUserGuest = ($userID==0?true:false);
        
        // get user roles
        $userRoles = $userAuthorizationRoles->getRoles($userID);
        
        // get page roles
        $pageDAO = new PageAuthorizationXML($xml);
        $pageRoles = $pageDAO->getRoles($routeToAuthorize);
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
}