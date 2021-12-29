<?php
namespace Lucinda\WebSecurity\Token;

/**
 * Exception thrown when token needs to be refreshed.
 */
class RegenerationException extends \Exception
{
    private mixed $payload;
    
    /**
     * Sets payload to use in regeneration.
     *
     * @param mixed $payload
     */
    public function setPayload(mixed $payload): void
    {
        $this->payload= $payload;
    }
    
    /**
     * Gets payload that was used in regeneration.
     *
     * @return mixed
     */
    public function getPayload(): mixed
    {
        return $this->payload;
    }
}
