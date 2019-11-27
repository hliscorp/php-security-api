<?php
namespace Lucinda\WebSecurity\Authorization\DAO;

use Lucinda\WebSecurity\Authorization\Result;
use Lucinda\WebSecurity\Authorization\ResultStatus;

/**
 * Encapsulates request authorization via DAOs.
 */
class Authorization
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
     * @return Result
     */
    public function authorize(PageAuthorizationDAO $page, UserAuthorizationDAO $user, string $httpRequestMethod): Result
    {
        $status = 0;
        $callbackURI = "";
        if ($page->getID()) {
            if (!$page->isPublic()) {
                if ($user->getID()) {
                    if (!$user->isAllowed($page, $httpRequestMethod)) {
                        $callbackURI = $this->loggedInFailureCallback;
                        $status = ResultStatus::FORBIDDEN;
                    } else {
                        // ok: do nothing
                        $status = ResultStatus::OK;
                    }
                } else {
                    $callbackURI = $this->loggedOutFailureCallback;
                    $status = ResultStatus::UNAUTHORIZED;
                }
            } else {
                // do nothing: it is allowed by default to display public panels
                $status = ResultStatus::OK;
            }
        } else {
            if ($user->getID()) {
                $callbackURI = $this->loggedInFailureCallback;
            } else {
                $callbackURI = $this->loggedOutFailureCallback;
            }
            $status = ResultStatus::NOT_FOUND;
        }
        return new Result($status, $callbackURI);
    }
}
