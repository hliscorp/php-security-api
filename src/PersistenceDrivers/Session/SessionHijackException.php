<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\WebSecurity\SecurityException;

/**
 * Exception thrown when someone attempts to hack your site.
 */
class SessionHijackException extends SecurityException
{
}
