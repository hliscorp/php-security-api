<?php
/**
 * Enum that contains all available authorization statuses.
 */
interface AuthorizationResultStatus {
	const OK = 5;
	const UNAUTHORIZED = 6;
	const FORBIDDEN = 7;
	const NOT_FOUND = 8;
}

/**
 * Encapsulates request authorization results.
 */
class AuthorizationResult {

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