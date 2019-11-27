<?php
namespace Lucinda\WebSecurity\Authorization\DAO;

use Lucinda\WebSecurity\Authorization\AuthorizationResult;
use Lucinda\WebSecurity\Authorization\AuthorizationResultStatus;

/**
 * Encapsulates request authorization via DAOs.
 */
class DAOAuthorization
{
    private $loggedInFailureCallback;
    private $loggedOutFailureCallback;
    
    /**
     * Creates an object
     *
     * @param string $loggedInFailureCallback Callback page to use when authorization fails for logged in users.
     * @param string $loggedOutFailureCallback Callback page to use when authorization fails for logged out (guest) users.
     */
    public function __construct(string $loggedInFailureCallback, string $loggedOutFailureCallback): void
    {
        $this->loggedInFailureCallback = $loggedInFailureCallback;
        $this->loggedOutFailureCallback = $loggedOutFailureCallback;
    }
    
    /**
     * Performs an authorization task
     *
     * @param PageAuthorizationDAO $page
     * @param UserAuthorizationDAO $user
     * @param string $httpRequestMethod
     * @return AuthorizationResult
     */
    public function authorize(PageAuthorizationDAO $page, UserAuthorizationDAO $user, string $httpRequestMethod): AuthorizationResult
    {
        $status = 0;
        $callbackURI = "";
        if ($page->getID()) {
            if (!$page->isPublic()) {
                if ($user->getID()) {
                    if (!$user->isAllowed($page, $httpRequestMethod)) {
                        $callbackURI = $this->loggedInFailureCallback;
                        $status = AuthorizationResultStatus::FORBIDDEN;
                    } else {
                        // ok: do nothing
                        $status = AuthorizationResultStatus::OK;
                    }
                } else {
                    $callbackURI = $this->loggedOutFailureCallback;
                    $status = AuthorizationResultStatus::UNAUTHORIZED;
                }
            } else {
                // do nothing: it is allowed by default to display public panels
                $status = AuthorizationResultStatus::OK;
            }
        } else {
            if ($user->getID()) {
                $callbackURI = $this->loggedInFailureCallback;
            } else {
                $callbackURI = $this->loggedOutFailureCallback;
            }
            $status = AuthorizationResultStatus::NOT_FOUND;
        }
        return new AuthorizationResult($status, $callbackURI);
    }
}
