<?php
namespace Lucinda\WebSecurity\Token;


/**
 * Encapsulates data encryption over openssl using AES-256 cypher.
 */
class Encryption
{
    const CYPHER_METHOD = "AES-256-CBC";
    
    private $salt;
    
    /**
     * Creates an encryption instance using a salt password that's going to be used in encryption/decryption.
     * @param string $salt Encryption password.
     */
    public function __construct(string $salt): void
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
        $ivlen = openssl_cipher_iv_length(self::CYPHER_METHOD);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($data, self::CYPHER_METHOD, $this->salt, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext_raw === false) {
            throw new EncryptionException("Encryption failed!");
        }
        $hmac = hash_hmac('sha256', $ciphertext_raw, $this->salt, true);
        return base64_encode($iv.$hmac.$ciphertext_raw);
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
        $c = base64_decode($data);
        $ivlen = openssl_cipher_iv_length(self::CYPHER_METHOD);
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len=32);
        $ciphertext_raw = substr($c, $ivlen+$sha2len);
        $original_plaintext = @openssl_decrypt($ciphertext_raw, self::CYPHER_METHOD, $this->salt, OPENSSL_RAW_DATA, $iv);
        if ($original_plaintext === false) {
            throw new EncryptionException("Decryption failed!");
        }
        $calcmac = hash_hmac('sha256', $ciphertext_raw, $this->salt, true);
        if (!hash_equals($hmac, $calcmac)) {
            throw new EncryptionException("Decryption failed!");
        }
        return $original_plaintext;
    }
}
