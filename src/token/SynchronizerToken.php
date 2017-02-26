<?php
require_once("Encryption.php");
require_once("TokenException.php");

/**
 * Encapsulates a SynchronizerToken, to be used for CSRF prevention or for stateless replacement of sessions.
 * https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
 */
final class SynchronizerToken {
	private $ip;
	private $secret;
	
	/**
	 * Constructs a synchronizer token.
	 * 
     * @param string $ip Ip address for whom token will be registered.
     * @param string $secret Strong encryption/decryption password. Check: http://randomkeygen.com/
	 */
	public function __construct($ip, $secret) {
		$this->ip = $ip;
		$this->secret = $secret;
	}
	
    /**
     * Creates a token.
     * 
     * @param mixed $userID Unique user identifier for whom token will be registered
     * @param integer $expirationTime Time by which token expires.
     * @throws EncryptionException If encryption of token fails.
     * @return string Encrypted token.
     */
    public function encode($userID, $expirationTime=3600) {
        $currentTime = time();
        $encryption = new Encryption($this->secret);
        return $encryption->encrypt($userID."#".$this->ip."#".$currentTime."#".($currentTime+$expirationTime)); 
    }
    
    /**
     * Decodes a token and returns user id.
     * 
     * @param string $token Encrypted token.
     * @param number $maximumLifetime Time by which token should be regenerated.
     * @throws TokenException If token fails validations.
     * @throws TokenRegenerationException If token needs to be refreshed
     * @throws TokenExpiredException If token expired beyond regeneration threshold. 
     * @throws EncryptionException If decryption of token fails.
     * @return mixed Unique user identifier.
     */
    public function decode($token, $maximumLifetime=0) {
        $encryption = new Encryption($this->secret);
        $decryptedValue = $encryption->decrypt($token);
        $parts = explode("#", $decryptedValue);
        
        // validate token
        if($this->ip!=$parts[1]) {
            throw new TokenException("Token was issued from a different ip!");
        }
        $currentTime = time();
        if($currentTime > $parts[3]) {
            throw new TokenExpiredException("Token has expired!");
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