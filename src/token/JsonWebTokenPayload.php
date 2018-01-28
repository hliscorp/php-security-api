<?php
/**
 * Encapsulates a JSON Web Token payload. More info:
* https://azure.microsoft.com/en-us/documentation/articles/active-directory-token-and-claims/
*/
class JsonWebTokenPayload {
    private $issuer;
    private $subject;
    private $audience;
    private $endTime;
    private $startTime;
    private $issuedTime;
    private $id;
    private $custom = array();
    
    public function __construct($data= array()) {
    	if(!empty($data)) {
    		foreach($data as $key=>$value){
    			switch($key) {
    				case "iss":
    					$this->issuer = $value;
    					break;
    				case "sub":
    					$this->subject = $value;
    					break;
    				case "aud":
    					$this->audience = $value;
    					break;
    				case "exp":
    					$this->endTime = $value;
    					break;
    				case "nbf":
    					$this->startTime = $value;
    					break;
    				case "iat":
    					$this->issuedTime = $value;
    					break;
    				case "jti":
    					$this->id = $value;
    					break;
    				default:
    					$this->custom[$key] = $value;
    					break;
    			}		
    		}
    	}
    }
    
    /**
     * Sets security token service (STS) that issued the JWT.
     *
     * @param string $value
     */
    public function setIssuer($value) {
        $this->issuer = $value;
    }

    /**
     * Gets security token service (STS) that issued the JWT.
     *
     * @return string
     */
    public function getIssuer() {
        return $this->issuer;
    }

    /**
     * Sets user of an application of JWT.
     *
     * @param mixed $userID Unique user identifier.
     */
    public function setSubject($userID) {
        $this->subject = $userID;
    }

    /**
     * Gets user of JWT.
     *
     * @return string
     */
    public function getSubject() {
        return $this->subject;
    }

    /**
     * Sets recipients (site) that the JWT is intended for.
     *
     * @param string $value
     */
    public function setAudience($value) {
        $this->audience = $value;
    }

    /**
     * Gets recipients (site) that the JWT is intended for.
     *
     * @return string
     */
    public function getAudience() {
        return $this->audience;
    }

    /**
     * Sets time by which token expires.
     *
     * @param integer $value
     */
    public function setEndTime($value) {
        $this->endTime = $value;
    }

    /**
     * Gets time by which token expires.
     *
     * @return integer
     */
    public function getEndTime() {
        return $this->endTime;
    }

    /**
     * Sets time by which token starts.
     *
     * @param integer $value
     */
    public function setStartTime($value) {
        $this->startTime = $value;
    }

    /**
     * Gets time by which token starts.
     *
     * @return integer
     */
    public function getStartTime() {
        return $this->startTime;
    }

    /**
     * Sets time when token was issued.
     *
     * @param integer $value
     */
    public function setIssuedTime($value) {
        $this->issuedTime = $value;
    }

    /**
     * Gets time by which token was issued.
     *
     * @return integer
     */
    public function getIssuedTime() {
        return $this->issuedTime;
    }

    /**
     * Sets application that is using the token to access a resource.
     *
     * @param string $value
     */
    public function setApplicationId($value) {
        $this->id = strtolower($value);
    }

    /**
     * Gets unique token identifier amidst multiple issuers.
     *
     * @return string
     */
    public function getApplicationId() {
        return $this->id;
    }
    
    /**
     * Sets custom payload parameter not among those specified in https://tools.ietf.org/html/rfc7519#section-4.1
     * 
     * @param string $name
     * @param string $value
     */
    public function setCustomClaim($name, $value) {
    	$this->custom[$key] = $value;
    }
    
    /**
     * Gets value of custom payload parameter.
     * 
     * @param string $name
     * @return NULL|string
     */
    public function getCustomClaim($name) {
    	return (isset($this->custom[$name])?$this->custom[$name]:null);
    }

    /**
     * Converts payload to array.
     *
     * @return array
     */
    public function toArray() {
        $response = array();
        if($this->issuer)           $response["iss"] = $this->issuer;
        if($this->subject)          $response["sub"] = $this->subject;
        if($this->audience)         $response["aud"] = $this->audience;
        if($this->endTime)          $response["exp"] = $this->endTime;
        if($this->startTime)        $response["nbf"] = $this->startTime;
        if($this->issuedTime)       $response["iat"] = $this->issuedTime;
        if($this->id)               $response["jti"] = $this->id;
        if(!empty($this->custom))	$response = array_merge($response, $this->custom);
        return $response;
    }
}