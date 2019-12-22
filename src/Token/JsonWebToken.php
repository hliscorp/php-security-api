<?php
namespace Lucinda\WebSecurity\Token;


/**
 * Encapsulates a JsonWebToken I/O.
 */
class JsonWebToken
{
    private $headers = array("typ"=>"JWT","alg"=>"HS256");
    private $salt;
    
    /**
     * Saves encryption password for later encoding or decoding
     *
     * @param string $salt Encryption password
     */
    public function __construct(string $salt)
    {
        $this->salt = $salt;
    }
    
    /**
     * Creates a JSON Web Token.
     *
     * @param JsonWebTokenPayload $sendPayload Payload to save in json web token.
     * @return string JWT token
     */
    public function encode(JsonWebTokenPayload $sendPayload): string
    {
        $encodedHeaders = base64_encode(json_encode($this->headers));
        $encodedPayload = base64_encode(json_encode($sendPayload->toArray()));
        $unsignedToken = $encodedHeaders.".".$encodedPayload;
        return $unsignedToken.".".base64_encode($this->getSignature($this->salt, $unsignedToken));
    }
    
    /**
     * Reads and validates a JSON Web Token
     *
     * @param string $token JWT token
     * @param integer $maximumLifetime Maximum lifetime of a JsonWebToken
     * @throws Exception When token fails validations.
     * @throws ExpiredException When token fails validations.
     * @throws RegenerationException When token needs to be regenerated.
     * @return JsonWebTokenPayload Payload retrieved from json web token.
     */
    public function decode(string $token, int $maximumLifetime=0): JsonWebTokenPayload
    {
        $parts = explode(".", $token);
        if (sizeof($parts)!=3) {
            throw new Exception("Token size is invalid!");
        }
        
        // check signature
        $unsignedToken = $parts[0].".".$parts[1];
        if (base64_decode($parts[2])!=$this->getSignature($this->salt, $unsignedToken)) {
            throw new Exception("Token decoding failed!");
        }
        
        // validate times
        $payload = json_decode(base64_decode($parts[1]), true);
        $currentTime = time();
        if (isset($payload["nbf"]) && $currentTime<$payload["nbf"]) {
            throw new ExpiredException("Token not started!");
        }
        if (isset($payload["exp"]) && $currentTime>$payload["exp"]) {
            throw new ExpiredException("Token has expired!");
        }
        if ($maximumLifetime && isset($payload["nbf"]) && ($currentTime-$payload["nbf"])>$maximumLifetime) {
            $exception = new RegenerationException("Token needs to be regenerated!");
            $exception->setPayload(new JsonWebTokenPayload($payload));
            throw $exception;
        }
        
        return new JsonWebTokenPayload($payload);
    }
    
    /**
     * Creates a JWT signature using HMAC-SHA256 algorithm and returns it.
     *
     * @param string $unsignedToken
     * @return string
     */
    private function getSignature(string $unsignedToken): string
    {
        return hash_hmac("SHA256", $unsignedToken, $this->salt);
    }
}
