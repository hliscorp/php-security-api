<?php
namespace Lucinda\WebSecurity\Authorization;

/**
 * Defines blueprints for user roles getting.
 */
interface UserRoles
{
    /**
     * Gets user roles
     *
     * @param mixed $userID
     * @return string[]
     */
    public function getRoles($userID): array;
}
