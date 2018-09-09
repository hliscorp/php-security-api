<?php
namespace Lucinda\WebSecurity;
require_once(dirname(__DIR__)."/SecurityException.php");
/**
 * Exception thrown when someone attempts to hack your site.
 */
class SessionHijackException extends SecurityException{}