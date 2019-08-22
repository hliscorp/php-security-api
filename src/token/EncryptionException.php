<?php
namespace Lucinda\WebSecurity;

require_once(dirname(__DIR__)."/SecurityException.php");
/**
 * Exception thrown when an attempt is made to encrypt/decrypt an invalid token.
 */
class EncryptionException extends SecurityException
{
}
