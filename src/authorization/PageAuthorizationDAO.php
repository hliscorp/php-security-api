<?php
namespace Lucinda\WebSecurity;
/**
 * Defines blueprints for a DAO that checks requested page access levels in database.
 */
interface PageAuthorizationDAO {
	/**
	 * Checks if current page does not require being logged in.
	 * 
	 * @return boolean
	 */
    function isPublic();
    
    /**
     * Gets detected id of page requested
     * 
     * @return integer
     */
    function getID();
}