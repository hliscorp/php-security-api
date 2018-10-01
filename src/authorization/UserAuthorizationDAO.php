<?php
namespace Lucinda\WebSecurity;
/**
 * Defines blueprints for a DAO that checks logged in user's access levels in database.
 */
interface UserAuthorizationDAO {
	/**
	 * Checks if current user is allowed to access a page.
	 * 
	 * @param PageAuthorizationDAO $page
	 * @param string $httpRequestMethod
	 * @return boolean
	 */
    function isAllowed(PageAuthorizationDAO $page, $httpRequestMethod);
    
    /**
     * Gets saved id of logged in user
     * @return integer
     */
    function getID();
}