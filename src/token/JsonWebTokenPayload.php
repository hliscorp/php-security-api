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
     * Converts payload to array.
     *
     * @return array
     */
    public function export() {
        $response = array();
        if($this->issuer)           $response["iss"] = $this->issuer;
        if($this->subject)          $response["sub"] = $this->subject;
        if($this->audience)         $response["aud"] = $this->audience;
        if($this->endTime)          $response["exp"] = $this->endTime;
        if($this->startTime)        $response["nbf"] = $this->startTime;
        if($this->issuedTime)       $response["iat"] = $this->issuedTime;
        if($this->id)               $response["jti"] = $this->id;
        return $response;
    }

    /**
     * Converts array into payload
     *
     * @param array $data
     * @throws TokenException If tokens don't validate.
     */
    public function import($data) {
        // validate
        if($this->audience && (empty($data["aud"]) || $data["aud"]!=$this->audience))   throw new TokenException("aud doesn't match");
        if($this->id && (empty($data["jti"]) || $data["jti"]!=$this->id))               throw new TokenException("jti doesn't match");
        if($this->issuer && (empty($data["iss"]) || $data["iss"]!=$this->issuer))       throw new TokenException("iss doesn't match");
        if($this->subject && (empty($data["sub"]) || $data["sub"]!=$this->subject))     throw new TokenException("sub doesn't match");
        
        // save
        foreach($data as $key=>$value){
            if($key == "iss")               $this->issuer = $value;
            else if($key == "sub")          $this->subject = $value;
            else if($key == "aud")          $this->audience = $value;
            else if($key == "exp")          $this->endTime = $value;
            else if($key == "nbf")          $this->startTime = $value;
            else if($key == "iat")          $this->issuedTime = $value;
            else                            $this->id = $value;
        }
    }
}