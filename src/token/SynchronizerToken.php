<?php
require_once("../Encryption.php");
require_once("TokenException.php");

/**
 * Encapsulates a SynchronizerToken, to be used for CSRF prevention or for stateless replacement of sessions.
 * https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
 */
final class SynchronizerToken {
    /**
     * Creates a token.
     * 
     * @param mixed $userID Unique user identifier for whom token will be registered
     * @param string $ip Ip address for whom token will be registered.
     * @param string $secret Secret encryption password. Check: http://randomkeygen.com/
     * @param integer $expirationTime Time by which token expires.
     * @throws EncryptionException If encryption of token fails.
     * @return string Encrypted token.
     */
    public function encode($userID, $ip, $secret, $expirationTime=3600) {
        $currentTime = time();
        $encryption = new Encryption($secret);
        return $encryption->encrypt($userID."#".$ip."#".$currentTime."#".($currentTime+$expirationTime)); 
    }
    
    /**
     * Decodes a token and returns user id.
     * 
     * @param string $token Encrypted token.
     * @param string $ip Ip address that must match that of token.
     * @param string $secret Secret decryption password (must be same as encryption password).
     * @param number $maximumLifetime Time by which token should be regenerated.
     * @throws TokenException If token fails validations.
     * @throws TokenRegenerationException If token needs to be refreshed
     * @return mixed Unique user identifier.
     */
    public function decode($token, $ip, $secret, $maximumLifetime=0) {
        $encryption = new Encryption($secret);
        $decryptedValue = $encryption->decrypt($token);
        $parts = explode("#", $decryptedValue);
        
        // validate token
        if($ip!=$parts[1]) {
            throw new TokenException("Token was issued from a different ip!");
        }
        $currentTime = time();
        if($currentTime > $parts[3]) {
            throw new TokenException("Token has expired!");
        }
        if($maximumLifetime && ($currentTime-$parts[2])>$maximumLifetime) {
        	$tre = new TokenRegenerationException("Token needs to be regenerated!");
        	$tre->setUserId($parts[0]);
            throw $tre;
        }
        
        // return user identifier
        return $parts[0];
    }
}