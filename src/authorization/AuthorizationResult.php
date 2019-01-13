<?php
namespace Lucinda\WebSecurity;
require_once("AuthorizationResultStatus.php");

/**
 * Encapsulates request authorization results.
 */
class AuthorizationResult {

    private $status;
    private $callbackURI;

    /**
     * Saves authorization result encapsulated by AuthorizationResultStatus enum along with callback URI
     * 
     * @param AuthorizationResultStatus $status
     * @param string $callbackURI
     */
    public function __construct($status, $callbackURI) {
        $this->status = $status;
        $this->callbackURI = $callbackURI;
    }

    /**
     * Gets authorization status.
     *
     * @return AuthorizationResultStatus
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