<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Encapsulates data encryption over openssl using AES-256 cypher.
 */
class Encryption
{
    public const CYPHER_METHOD = "AES-256-CBC";

    private string $salt;

    /**
     * Creates an encryption instance using a salt password that's going to be used in encryption/decryption.
     * @param string $salt Encryption password.
     */
    public function __construct(string $salt)
    {
        $this->salt = $salt;
    }

    /**
     * Encrypts data and returns encrypted value.
     *
     * @param string $data Value to encrypt.
     * @throws EncryptionException If encryption fails.
     * @return string Encrypted representation of data.
     */
    public function encrypt(string $data): string
    {
        $iv = $this->getIv();
        $key = openssl_encrypt(
            $data,
            self::CYPHER_METHOD,
            $this->salt,
            0,
            $iv
        );
        if ($key===false) {
            throw new EncryptionException("Encryption failed!");
        }
        return base64_encode($key.":".base64_encode($iv));
    }

    /**
     * Decrypts data and returns decrypted value.
     *
     * @param string $data Encrypted representation of data.
     * @throws EncryptionException If decryption fails.
     * @return string Decrypted data.
     */
    public function decrypt(string $data): string
    {
        $parts = explode(":", base64_decode($data));
        if (!isset($parts[1])) {
            throw new EncryptionException("Decryption failed!");
        }
        $val = openssl_decrypt(
            $parts[0],
            self::CYPHER_METHOD,
            $this->salt,
            0,
            base64_decode($parts[1])
        );
        if ($val===false) {
            throw new EncryptionException("Encryption failed!");
        }
        return $val;
    }

    /**
     * Gets a non-NULL initialized vector
     *
     * @return string
     */
    private function getIv(): string
    {
        return openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::CYPHER_METHOD));
    }
}
