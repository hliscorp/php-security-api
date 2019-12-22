<?php
namespace Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Exception;

/**
 * Exception thrown when an attempt is made to encrypt/decrypt an invalid token.
 */
class EncryptionException extends Exception
{
}
