<?php
namespace Lucinda\WebSecurity\Authorization\XML;


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
