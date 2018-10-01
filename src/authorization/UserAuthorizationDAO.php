<?php
namespace Lucinda\WebSecurity;
/**
 * Defines blueprints for a DAO that checks logged in user's access levels in database.
 */
abstract class UserAuthorizationDAO {
    protected $userID;

    /**
     * UserAuthorizationDAO constructor.
     * @param mixed $userID Unique user identifier
     */
    public function __construct($userID) {
        $this->userID = $userID;
    }

	/**
	 * Checks if current user is allowed to access a page.
	 * 
	 * @param PageAuthorizationDAO $page
	 * @param string $httpRequestMethod Current HTTP request method
	 * @return boolean
	 */
    abstract public function isAllowed(PageAuthorizationDAO $page, $httpRequestMethod);
    
    /**
     * Gets saved id of logged in user
     * @return integer
     */
    public function getID() {
        return $this->userID;
    }
}