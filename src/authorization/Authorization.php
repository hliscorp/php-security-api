<?php
require_once("AuthorizationResult.php");

/**
 * Encapsulates request authorization.
 */
class Authorization {
    private $authorizedHomePage;
    private $guestHomePage;
    
    /**
     * Creates an object
     * 
     * @param string $authorizedHomePage
     * @param string $guestHomePage
     */
    public function __construct($authorizedHomePage = "index", $guestHomePage = "login") {
        $this->authorizedHomePage = $authorizedHomePage;
        $this->guestHomePage = $guestHomePage;
    }
    
    /**
     * Performs an authorization task
     * 
     * @param Page $page
     * @param User $user
     * @return AuthorizationResult
     */
    public function authorize(Page $page, User $user = null) {
        $status = 0;
        $callbackURI = "";
        if($page->isFound()) {
            if(!$page->isPublic()) {
                if($user) {
                    if(!$user->isAllowed($page)) {
                        $callbackURI = $this->authorizedHomePage;
                        $status = AuthorizationResult::STATUS_NOT_ALLOWED;
                    } else {
                        // ok: do nothing
                        $status = AuthorizationResult::STATUS_OK;
                    }
                } else {
                    $callbackURI = $this->guestHomePage;
                    $status = AuthorizationResult::STATUS_NOT_ALLOWED;
                }
            } else {
                // do nothing: it is allowed by default to display public panels
                $status = AuthorizationResult::STATUS_OK;
            }
        } else {
            if($user) {
                $callbackURI = $this->authorizedHomePage;
            } else {
                $callbackURI = $this->guestHomePage;
            }
            $status = AuthorizationResult::STATUS_NOT_FOUND;
        }
        return new AuthorizationResult($status,$callbackURI);
    }
    
    
}