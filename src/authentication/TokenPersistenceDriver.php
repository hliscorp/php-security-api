<?php
class TokenPersistenceDriver implements PersistenceDriver {
	private $current_ip;
	
	private $secret;
	private $expirationTime;
	private $regenerationTime;
	
	private $token;
	
	public function __construct($secret, $expirationTime = 3600, $regenerationTime = 60) {
		$this->current_ip = (isset($_SERVER["REMOTE_ADDR"])?$_SERVER["REMOTE_ADDR"]:"");
		
		$this->secret = $secret;
		$this->expirationTime = $expirationTime;
		$this->regenerationTime = $regenerationTime;
	}
	
	public function load() {
		if(!isset($_SERVER["HTTP_AUTHORIZATION"]) || strpos($_SERVER["HTTP_AUTHORIZATION"],"Token ")!==0) {
			return;
		}
		
		$token = substr($_SERVER["HTTP_AUTHORIZATION"],6);
		// decode token
		try {
			$userID = SynchronizerToken::decode($token,$this->current_ip,$this->secret, $this->regenerationTime);
		} catch(TokenRegenerationException $e) {
			$userID = $e->getUserId();
			$this->token = SynchronizerToken::encode($userID, $this->current_ip, $this->secret, $this->expirationTime);
		}
		// regenerate token
		return $userID;
	}
	
	public function save($userID) {
		$this->token = SynchronizerToken::encode($userID, $this->current_ip, $this->secret, $this->expirationTime);
	}
	
	public function getToken() {
		return $this->token;
	}
}