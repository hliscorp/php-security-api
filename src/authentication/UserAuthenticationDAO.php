<?php
/**
 * Defines blueprints for a DAO that forwards authentication to database.
 */
interface UserAuthenticationDAO {
	/**
	 * Performs a login operation in DB
	 * 
	 * @param LoginCredentials $credentials User-password credentials needed by standard login.
	 * @return mixed Unique user identifier (typically an integer)
	 */
    function login(LoginCredentials $credentials);
    
    /**
     * Performs a logout operation in DB
     * 
     * @param mixed $userID Unique user identifier (typically an integer)
     */
    function logout($userID);
}