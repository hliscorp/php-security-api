<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Generates a password of fixed length to use as salt when tokens are generated
 */
class SaltGenerator
{
    private string $salt;

    /**
     * Performs generation process.
     *
     * @param int $length
     * @throws \Exception
     */
    public function __construct(int $length)
    {
        $this->setSalt($length);
    }

    /**
     * Generates a salt of fixed length to use as salt/password in token generation
     *
     * @param int $length
     * @throws \Exception
     */
    private function setSalt(int $length): void
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
