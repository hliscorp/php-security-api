<?php
namespace Lucinda\WebSecurity;

/**
 * Defines blueprints for user roles getting.
 */
interface UserAuthorizationRoles
{
    /**
     * Gets user roles
     *
     * @param mixed $userID
     * @return string[]
     */
    public function getRoles($userID): array;
}
