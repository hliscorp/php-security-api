<?php
/**
 * Enum that contains all available authorization statuses.
 */
class AuthorizationResultStatus {
	const OK = 1;
	const UNAUTHORIZED = 2;
	const FORBIDDEN = 3;
	const NOT_FOUND = 4;
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