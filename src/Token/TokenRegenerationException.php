<?php
namespace Lucinda\WebSecurity;

/**
 * Exception thrown when token needs to be refreshed.
 */
class TokenRegenerationException extends \Exception
{
    private $payload;
    
    /**
     * Sets payload to use in regeneration.
     *
     * @param mixed $payload
     */
    public function setPayload($payload): void
    {
        $this->payload= $payload;
    }
    
    /**
     * Gets payload that was used in regeneration.
     *
     * @return mixed
     */
    public function getPayload()
    {
        return $this->payload;
    }
}
