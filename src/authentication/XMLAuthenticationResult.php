<?php
require_once("AuthenticationResult.php");

/**
 * Encapsulates XML authentication response
 */
class XMLAuthenticationResult extends AuthenticationResult {
	private $roles;
	
	/**
	 * Sets roles user belongs to.
	 * 
	 * @param string[] $roles
	 */
	public function setRoles($roles) {
		$this->roles = $roles;
	}
	
	/**
	 * Returns roles user belongs to.
	 * 
	 * @return string[]
	 */
	public function getRoles() {
		return $this->roles;
	}
}