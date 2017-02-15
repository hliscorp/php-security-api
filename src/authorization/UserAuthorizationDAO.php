<?php
/**
 * Defines blueprints for a DAO that checks logged in user's access levels in database.
 */
interface UserAuthorizationDAO {
	/**
	 * Checks if current user is allowed to access a page.
	 * 
	 * @param PageAuthorizationDAO $page
	 * @return boolean
	 */
    function isAllowed(PageAuthorizationDAO $page);
    
    /**
     * Saves id of logged in user.
     * 
     * @param integer $userID
     */
    function setID($userID);
    
    /**
     * Gets saved id of logged in user
     * @return integer
     */
    function getID();
}