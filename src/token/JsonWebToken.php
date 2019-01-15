<?php
namespace Lucinda\WebSecurity;
require_once("JsonWebTokenPayload.php");
require_once("TokenException.php");
require_once("TokenExpiredException.php");
require_once("TokenRegenerationException.php");

/**
 * Encapsulates a JsonWebToken I/O.
 */
class JsonWebToken {
	private $headers = array("typ"=>"JWT","alg"=>"HS256");
	private $secret;
	
	/**
	 * Saves encryption password for later encoding or decoding
	 * 
	 * @param string $secret Encryption password
	 */
	public function __construct($secret) {
		$this->secret = $secret;
	}
	
	/**
	 * Creates a JSON Web Token.
	 *
	 * @param JsonWebTokenPayload $sendPayload Payload to save in json web token.
	 * @return string JWT token
	 */
	public function encode(JsonWebTokenPayload $sendPayload) {
		$encodedHeaders = base64_encode(json_encode($this->headers));
		$encodedPayload = base64_encode(json_encode($sendPayload->toArray()));
		$unsignedToken = $encodedHeaders.".".$encodedPayload;
		return $unsignedToken.".".base64_encode($this->getSignature($this->secret, $unsignedToken));
	}
	
	/**
	 * Reads and validates a JSON Web Token
	 *
	 * @param string $token JWT token
	 * @param integer $maximumLifetime Maximum lifetime of a JsonWebToken
	 * @throws TokenException When token fails validations.
	 * @throws TokenExpiredException When token fails validations.
	 * @throws TokenRegenerationException When token needs to be regenerated.
	 * @return JsonWebTokenPayload Payload retrieved from json web token.
	 */
	public function decode($token, $maximumLifetime=0) {
		$parts = explode(".", $token);
		if(sizeof($parts)!=3) throw new TokenException("Token size is invalid!");
		
		// check signature
		$unsignedToken = $parts[0].".".$parts[1];
		if(base64_decode($parts[2])!=$this->getSignature($this->secret, $unsignedToken)) {
			throw new TokenException("Token decoding failed!");
		}
		
		// validate times
		$payload = json_decode(base64_decode($parts[1]),true);
		$currentTime = time();
		if(isset($payload["nbf"]) && $currentTime<$payload["nbf"]) {
			throw new TokenExpiredException("Token not started!");
		}
		if(isset($payload["exp"]) && $currentTime>$payload["exp"]) {
			throw new TokenExpiredException("Token has expired!");
		}
		if($maximumLifetime && isset($payload["nbf"]) && ($currentTime-$payload["nbf"])>$maximumLifetime) {
			$exception = new TokenRegenerationException("Token needs to be regenerated!");
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
	private function getSignature($unsignedToken) {
		return hash_hmac("SHA256", $unsignedToken, $this->secret);
	}
}