<?php
namespace Lucinda\WebSecurity;
require_once("PersistenceDriver.php");

/**
 * Encapsulates a driver that persists unique user identifier into a crypted self-regenerating token that
 * must be sent by clients via Authorization header of bearer type.
 */
abstract class TokenPersistenceDriver implements PersistenceDriver {
	protected $accessToken;
	
	/**
	 * Sets access token value based on contents of HTTP authorization header of "bearer" type
	 */
	public function setAccessToken() {
		if(!isset($_SERVER["HTTP_AUTHORIZATION"]) || stripos($_SERVER["HTTP_AUTHORIZATION"],"Bearer ")!==0) {
			return;
		}
		
		$this->accessToken = trim(substr($_SERVER["HTTP_AUTHORIZATION"],7));
	}
	
	/**
	 * Gets access token value.
	 * 
	 * @return string
	 */
	public function getAccessToken() {
		return $this->accessToken;
	}
}