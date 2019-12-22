<?php
namespace Lucinda\WebSecurity\Authorization;

/**
 * Enum that contains all available authorization statuses via following constants:
 * - OK: authorization was successful
 * - UNAUTHORIZED: authorization failed because user is not authenticated
 * - FORBIDDEN: authorization failed because authenticated user is not allowed access to requested resource
 * - NOT_FOUND: authorization failed because no authorization policy could be found for requested resource
 */
interface ResultStatus
{
    const OK = 6;
    const UNAUTHORIZED = 7;
    const FORBIDDEN = 8;
    const NOT_FOUND = 9;
}
