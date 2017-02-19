<?php
/**
 * Encapsulates information about remote logged in user on OAuth2 provider.
 */
class OAuth2UserInformation {
	private $id;
	private $name;
	private $email;
	
	/**
	 * Creates an object.
	 * 
	 * @param integer $id Remote user id.
	 * @param string $name Remote user name.
	 * @param string $email Remote user email.
	 */
	public function __construct($id, $name, $email) {
		$this->id = $id;
		$this->name = $name;
		$this->email = $email;
	}
	
	/**
	 * Gets remote user id.
	 * 
	 * @return integer
	 */
	public function getId() {
		return $this->id;
	}
	
	/**
	 * Gets remote user name.
	 * 
	 * @return string
	 */
	public function getName() {
		return $this->name;
	}
	
	/**
	 * Gets remote user email.
	 * 
	 * @return string
	 */
	public function getEmail() {
		return $this->email;
	}
}