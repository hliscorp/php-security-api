<?php
namespace Lucinda\WebSecurity;
/**
 * Enum that contains all available authentication statuses.
 */
interface AuthenticationResultStatus {
    const LOGIN_OK = 1;
    const LOGIN_FAILED = 2;
    const LOGOUT_OK = 3;
    const LOGOUT_FAILED = 4;
    const DEFERRED = 5;
}