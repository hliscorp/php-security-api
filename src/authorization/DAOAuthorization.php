<?php
require_once("AuthorizationResult.php");
require_once("PageAuthorizationDAO.php");
require_once("UserAuthorizationDAO.php");

/**
 * Encapsulates request authorization via DAOs.
 */
class DAOAuthorization {
    private $loggedInFailureCallback;
    private $loggedOutFailureCallback;
    
    /**
     * Creates an object
     * 
     * @param string $loggedInFailureCallback Callback page to use when authorization fails for logged in users.
     * @param string $loggedOutFailureCallback Callback page to use when authorization fails for logged out (guest) users.
     */
    public function __construct($loggedInFailureCallback, $loggedOutFailureCallback) {
        $this->loggedInFailureCallback = $loggedInFailureCallback;
        $this->loggedOutFailureCallback = $loggedOutFailureCallback;
    }
    
    /**
     * Performs an authorization task
     * 
     * @param PageAuthorizationDAO $page
     * @param UserAuthorizationDAO $user
     * @return AuthorizationResult
     */
    public function authorize(PageAuthorizationDAO $page, UserAuthorizationDAO $user = null) {
        $status = 0;
        $callbackURI = "";
        if($page->isFound()) {
            if(!$page->isPublic()) {
                if($user) {
                    if(!$user->isAllowed($page)) {
                        $callbackURI = $this->loggedInFailureCallback;
                        $status = AuthorizationResult::STATUS_FORBIDDEN;
                    } else {
                        // ok: do nothing
                        $status = AuthorizationResult::STATUS_OK;
                    }
                } else {
                    $callbackURI = $this->loggedOutFailureCallback;
                    $status = AuthorizationResult::STATUS_UNAUTHORIZED;
                }
            } else {
                // do nothing: it is allowed by default to display public panels
                $status = AuthorizationResult::STATUS_OK;
            }
        } else {
            if($user) {
                $callbackURI = $this->loggedInFailureCallback;
            } else {
                $callbackURI = $this->loggedOutFailureCallback;
            }
            $status = AuthorizationResult::STATUS_NOT_FOUND;
        }
        return new AuthorizationResult($status,$callbackURI);
    }
    
    
}