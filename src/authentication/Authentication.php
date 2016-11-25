<?php
/**
 * Implements authentication skeleton.
 */
interface Authentication {
    /**
     * Logins user
     * 
     * @param User $user Instance of user onto which login operation will be performed 
     * @param LoginCredentials $credentials Encapsulated login credentials
     * @return mixed Implementation-defined return.
     */
    function login(User $user, LoginCredentials $credentials);
    
    /**
     * Logs out user
     * 
     * @param User $user
     */
    function logout(User $user);
}