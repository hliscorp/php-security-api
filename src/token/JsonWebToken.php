<?php
require_once("JsonWebTokenPayload.php");
require_once("TokenException.php");

/**
 * Encapsulates a JsonWebToken I/O.
 */
final class JsonWebToken {
    private $headers = array("typ"=>"JWT","alg"=>"HS256");
    
    /**
     * Creates a JSON Web Token.
     * 
     * @param JsonWebTokenPayload $sendPayload Pre-filled payload.
     * @param string $secret Encryption password
     * @return string JWT token
     */
    public function encode(JsonWebTokenPayload $sendPayload, $secret) {
        $encodedHeaders = base64_encode(json_encode($this->headers));
        $encodedPayload = base64_encode(json_encode($sendPayload->export()));
        $unsignedToken = $encodedHeaders.".".$encodedPayload;
        return $unsignedToken.".".base64_encode($this->getSignature($secret,$unsignedToken));
    }
    
    /**
     * Reads and validates a JSON Web Token
     * 
     * @param string $token JWT token
     * @param string $secret
     * @param JsonWebTokenPayload $receivePayload Receive payload (can be filled for cross-verification).
     * @param integer $maximumLifetime Maximum lifetime of a JsonWebToken
     * @throws TokenException When token fails validations.
     * @throws TokenRegenerationException When token needs to be regenerated.
     * @return JsonWebTokenPayload Receive payload.
     */
    public function decode($token, $secret, JsonWebTokenPayload $receivePayload, $maximumLifetime=0) {
        $parts = explode(".", $token);
        if(sizeof($parts)!=3) throw new TokenException("Token size is invalid!");
        
        // check signature
        $unsignedToken = $parts[0].".".$parts[1];
        if(base64_decode($parts[2])!=$this->getSignature($secret, $unsignedToken)) {
            throw new TokenException("Token decoding failed!");
        }
        
        // validate times
        $payload = json_decode(base64_decode($parts[1]),true);
        $currentTime = time();
        if(isset($payload["nbf"]) && $currentTime<$payload["nbf"]) {
            throw new TokenException("Token not started!");
        }
        if(isset($payload["exp"]) && $currentTime>$payload["exp"]) {
            throw new TokenException("Token has expired!");
        }
        if($maximumLifetime && isset($payload["iat"]) && ($currentTime-$payload["iat"])>$maximumLifetime) {
            throw new TokenRegenerationException("Token needs to be regenerated!");
        }
        
        // import payload
        $receivePayload->import($payload);
        return $receivePayload;
    }
        
    /**
     * Creates a JWT signature using HMAC-SHA256 algorithm and returns it.
     * 
     * @param string $secret
     * @param string $unsignedToken
     * @return string
     */
    private function getSignature($secret, $unsignedToken) {
        return hash_hmac("SHA256", $unsignedToken, $secret);
    }
}