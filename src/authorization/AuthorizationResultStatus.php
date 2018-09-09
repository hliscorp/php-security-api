<?php
namespace Lucinda\WebSecurity;
/**
 * Enum that contains all available authorization statuses.
 */
interface AuthorizationResultStatus {
    const OK = 6;
    const UNAUTHORIZED = 7;
    const FORBIDDEN = 8;
    const NOT_FOUND = 9;
}
