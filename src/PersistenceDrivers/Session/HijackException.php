<?php
namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\WebSecurity\Exception;

/**
 * Exception thrown when someone attempts to hack your site.
 */
class HijackException extends Exception
{
}
