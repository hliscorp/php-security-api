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
enum ResultStatus: int
{
    case LOGIN_OK = 1;
    case LOGIN_FAILED = 2;
    case LOGOUT_OK = 3;
    case LOGOUT_FAILED = 4;
    case DEFERRED = 5;
}
