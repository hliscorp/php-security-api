<?php
/**
 * Encapsulates request authorization.
 */
class AuthorizationResult {
    // start enum
    const STATUS_OK = 1;
    const STATUS_UNAUTHORIZED = 2;
    const STATUS_FORBIDDEN = 3;
    const STATUS_NOT_FOUND = 4;
    // end enum

    private $status;
    private $callbackURI;

    /**
     * @param integer $status
     * @param string $callbackURI
     */
    public function __construct($status, $callbackURI) {
        $this->status = $status;
        $this->callbackURI = $callbackURI;
    }

    /**
     * Gets authorization status.
     *
     * @return string
     */
    public function getStatus() {
        return $this->status;
    }

    /**
     * Gets callback URI
     *
     * @return string
     */
    public function getCallbackURI() {
        return $this->callbackURI;
    }
}