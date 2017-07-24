<?php
/**
 * Enum that contains all available authorization statuses.
 */
interface AuthorizationResultStatus {
	const OK = 6;
	const UNAUTHORIZED = 7;
	const FORBIDDEN = 8;
	const NOT_FOUND = 9;
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