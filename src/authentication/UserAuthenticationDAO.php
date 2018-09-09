<?php
namespace Lucinda\WebSecurity;
/**
 * Defines blueprints for a DAO that forwards user-password authentication to database.
 */
interface UserAuthenticationDAO {
	/**
	 * Performs a login operation in DB
	 * 
	 * @param string $username Value of user name
	 * @param string $password Value of user password
	 * @param null|boolean $rememberMe Value of remember me option (if any)
	 * @return mixed Unique user identifier (typically an integer)
	 */
	function login($username, $password, $rememberMe=null);
    
    /**
     * Performs a logout operation in DB
     * 
     * @param mixed $userID Unique user identifier (typically an integer)
     */
    function logout($userID);
}