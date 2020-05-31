<?php
namespace Lucinda\WebSecurity\Authentication;

/**
 * Enum that contains all available authentication result statuses via following constants:
 * - LOGIN_OK: login was successful
 * - LOGIN_FAILED: login was unsuccessful (eg: password was wrong)
 * - LOGOUT_OK: logout was successful
 * - LOGOUT_FAILED: logout was unsuccessful (eg: user wasn't logged in)
 * - DEFERRED: login was deferred to a third party provider (eg: oauth2)
 */
interface ResultStatus
{
    const LOGIN_OK = 1;
    const LOGIN_FAILED = 2;
    const LOGOUT_OK = 3;
    const LOGOUT_FAILED = 4;
    const DEFERRED = 5;
}
