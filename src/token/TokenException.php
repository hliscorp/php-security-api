<?php
/**
 * Exception thrown when token fails validation.
 */
class TokenException extends Exception {}

/**
 * Exception thrown when token needs to be refreshed.
 */
class TokenRegenerationException extends Exception {}