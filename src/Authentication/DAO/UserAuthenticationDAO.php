<?php
namespace Lucinda\WebSecurity;

/**
 * Defines blueprints for a DAO that forwards user-password authentication to database.
 */
interface UserAuthenticationDAO
{
    /**
     * Performs a login operation in DB
     *
     * @param string $username Value of user name
     * @param string $password Value of user password
     * @return mixed Unique user identifier (typically an integer)
     */
    public function login(string $username, string $password);
    
    /**
     * Performs a logout operation in DB
     *
     * @param mixed $userID Unique user identifier (typically an integer)
     */
    public function logout($userID): void;
}
