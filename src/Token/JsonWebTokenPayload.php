<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Encapsulates a JSON Web Token payload. More info:
 * https://azure.microsoft.com/en-us/documentation/articles/active-directory-token-and-claims/
 */
class JsonWebTokenPayload
{
    private ?string $issuer = null;
    private int|string|null $subject = null;
    private ?string $audience = null;
    private ?int $endTime = null;
    private ?int $startTime = null;
    private ?int $issuedTime = null;
    private ?string $id = null;
    /**
     * @var array<string,string>
     */
    private array $custom = [];

    /**
     * Encapsulates JWT data received from client
     *
     * @param array<string,string|int> $data
     */
    public function __construct(array $data= [])
    {
        $correspondences = [
            "iss"=>"issuer",
            "sub"=>"subject",
            "aud"=>"audience",
            "exp"=>"endTime",
            "nbf"=>"startTime",
            "iat"=>"issuedTime",
            "jti"=>"id",
        ];
        if (!empty($data)) {
            foreach ($data as $key=>$value) {
                if (isset($correspondences[$key])) {
                    $field = $correspondences[$key];
                    $this->$field = $value;
                } else {
                    $this->custom[$key] = $value;
                }
            }
        }
    }

    /**
     * Sets security token service (STS) that issued the JWT.
     *
     * @param string $value
     */
    public function setIssuer(string $value): void
    {
        $this->issuer = $value;
    }

    /**
     * Gets security token service (STS) that issued the JWT.
     *
     * @return string|null
     */
    public function getIssuer(): ?string
    {
        return $this->issuer;
    }

    /**
     * Sets user of an application of JWT.
     *
     * @param int|string $userID Unique user identifier.
     */
    public function setSubject(int|string $userID): void
    {
        $this->subject = $userID;
    }

    /**
     * Gets user of JWT.
     *
     * @return int|string|null
     */
    public function getSubject(): int|string|null
    {
        return $this->subject;
    }

    /**
     * Sets recipients (site) that the JWT is intended for.
     *
     * @param string $value
     */
    public function setAudience(string $value): void
    {
        $this->audience = $value;
    }

    /**
     * Gets recipients (site) that the JWT is intended for.
     *
     * @return string|null
     */
    public function getAudience(): ?string
    {
        return $this->audience;
    }

    /**
     * Sets time by which token expires.
     *
     * @param int $value
     */
    public function setEndTime(int $value): void
    {
        $this->endTime = $value;
    }

    /**
     * Gets time by which token expires.
     *
     * @return int|null
     */
    public function getEndTime(): ?int
    {
        return $this->endTime;
    }

    /**
     * Sets time by which token starts.
     *
     * @param int $value
     */
    public function setStartTime(int $value): void
    {
        $this->startTime = $value;
    }

    /**
     * Gets time by which token starts.
     *
     * @return int|null
     */
    public function getStartTime(): ?int
    {
        return $this->startTime;
    }

    /**
     * Sets time when token was issued.
     *
     * @param int $value
     */
    public function setIssuedTime(int $value): void
    {
        $this->issuedTime = $value;
    }

    /**
     * Gets time by which token was issued.
     *
     * @return int|null
     */
    public function getIssuedTime(): ?int
    {
        return $this->issuedTime;
    }

    /**
     * Sets application that is using the token to access a resource.
     *
     * @param int|string $value
     */
    public function setApplicationId(int|string $value): void
    {
        $this->id = strtolower($value);
    }

    /**
     * Gets unique token identifier amidst multiple issuers.
     *
     * @return string|null
     */
    public function getApplicationId(): ?string
    {
        return $this->id;
    }

    /**
     * Sets custom payload parameter not among those specified in https://tools.ietf.org/html/rfc7519#section-4.1
     *
     * @param string $name
     * @param string $value
     */
    public function setCustomClaim(string $name, string $value): void
    {
        $this->custom[$name] = $value;
    }

    /**
     * Gets value of custom payload parameter or null if not found.
     *
     * @param  string $name
     * @return string|null
     */
    public function getCustomClaim(string $name): ?string
    {
        return ($this->custom[$name] ?? null);
    }

    /**
     * Converts payload to array.
     *
     * @return array<string,string>
     */
    public function toArray(): array
    {
        $correspondences = [
            "iss"=>"issuer",
            "sub"=>"subject",
            "aud"=>"audience",
            "exp"=>"endTime",
            "nbf"=>"startTime",
            "iat"=>"issuedTime",
            "jti"=>"id",
        ];
        $response = [];
        foreach ($correspondences as $key=>$value) {
            if ($val = $this->$value) {
                $response[$key] = $val;
            }
        }
        if (!empty($this->custom)) {
            $response = array_merge($response, $this->custom);
        }
        return $response;
    }
}
