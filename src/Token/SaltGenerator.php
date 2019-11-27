<?php
namespace Lucinda\WebSecurity;

/**
 * Generates a password of fixed length to use as salt when tokens are generated
 */
class SaltGenerator
{
    private $salt;
    
    /**
     * Performs generation process.
     * 
     * @param integer $length
     */
    public function __construct(int $length): void
    {
        $this->setSalt($length);
    }
    
    /**
     * Generates a salt of fixed length to use as salt/password in token generation
     *
     * @param integer $length
     * @return string
     */
    private function setSalt(int $length): string
    {
        $this->salt = substr(strtr(base64_encode(random_bytes($length)), '+', '.'), 0, $length);
    }    
    
    /**
     * Gets salt/password to use in token generation
     * 
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }
}
