<?php
/**
 * Encapsulates request authorization.
 */
class AuthorizationResult {
    // start enum
    const STATUS_OK = 1;
    const STATUS_NOT_ALLOWED = 2;
    const STATUS_NOT_FOUND = 3;
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
     * @return integer
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