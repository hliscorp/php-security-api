<?php
class RememberMeDriver extends PersistenceDriver {
	private $current_ip;
	
	private $parameterName;
	private $secret;
	private $expirationTime;
	private $isHttpOnly;
	private $isSecure;
	
	public function __construct($secret, $parameterName = "uid", $expirationTime = 86400, $isHttpOnly = false, $isSecure = false) {
		$this->current_ip = (isset($_SERVER["REMOTE_ADDR"])?$_SERVER["REMOTE_ADDR"]:"");

		$this->secret = $secret;
		$this->parameterName = $parameterName;
		$this->expirationTime = $expirationTime;
		$this->isHttpOnly = $isHttpOnly;
		$this->isSecure = $isSecure;
	}
	
	public function load() {
		if(empty($_COOKIE[$this->parameterName])) {
			return;
		}
		
		return SynchronizerToken::decode($_COOKIE[$this->parameterName],$this->current_ip,$this->secret);
	}
	
	public function save($userID) {
		$token = SynchronizerToken::encode($userID, $this->current_ip, $this->secret, $this->expirationTime);
		setcookie($this->parameterName, $token, $this->expirationTime, "", "", $this->isSecure, $this->isHttpOnly);
	}
	
	public function clear($userID) {
		setcookie ($this->parameterName, "", 1);
		setcookie ($this->parameterName, false);
		unset($_COOKIE[$this->parameterName]);
	}
}