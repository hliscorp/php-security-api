<?php
require_once("AuthenticationException.php");
require_once("XMLAuthenticationResult.php");

/**
 * Encapsulates authentication via XML ACL
 */
class XMLAuthentication {
	const ROLE_GUEST = "GUEST";
	private $xml;
	private $persistenceDrivers;
	
	/**
	 * Creates a form authentication object.
	 *
	 * @param UserAuthenticationDAO $dao Forwards operations to database via a DAO.
	 * @param PersistenceDriver[] $persistenceDrivers List of PersistentDriver entries that allow authenticated state to persist between requests.
	 * @throws AuthenticationException If one of persistenceDrivers entries is not a PersistentDriver
	 */
	public function __construct(SimpleXMLElement $xml, $persistenceDrivers = array()) {
		// check argument that it's instance of PersistenceDriver
		foreach($persistenceDrivers as $persistentDriver) {
			if(!($persistentDriver instanceof PersistenceDriver)) throw new AuthenticationException("Items must be instanceof PersistenceDriver");
		}
		
		// save pointers
		$this->xml = $xml;
		$this->persistenceDrivers = $persistenceDrivers;
	}
	
	/**
	 * Performs a login operation:
	 * - queries XML for an user id based on credentials
	 * - saves user_id in persistence drivers (if any)
	 *
	 * @param string $username Value of user name
	 * @param string $password Value of user password
	 * @return XMLAuthenticationResult Encapsulates result of login attempt.
	 * @throws AuthenticationException If POST parameters are invalid.
	 */
	public function login($username, $password) {
		$userID = null;
		$userRoles = array();
		
		// check rights
		$tmp = (array) $xml->users;
		$tmp = $tmp["user"];
		if(!is_array($tmp)) $tmp = array($tmp);
		foreach($tmp as $info) {
			$currentUserName = (string) $info['username'];
			$currentPassword = (string) $info['password'];
			if(!$currentUserName || !$currentPassword) throw new XMLException("XML tag users / user requires: username, password parameters");
			if($username == $currentUserName && $password = $currentPassword) {			
				$userID = (string) $info["id"];
				$roles = (string) $info["roles"];
				if(!$userID || !$roles) throw new XMLException("XML tag users / user requires: id, roles parameters");
				$tmp = explode(",",$roles);
				foreach($tmp as $role) {
					$userRoles[] = trim($role);
				}
			}
		}
		
		
		if(empty($userID)) {
			$result = new XMLAuthenticationResult(AuthenticationResultStatus::LOGIN_FAILED);
			$result->setRoles(array(self::ROLE_GUEST));
			return $result;
		} else {
			// saves in persistence drivers
			foreach($this->persistenceDrivers as $persistenceDriver) {
				$persistenceDriver->save($userID);
			}
			// returns result
			$result = new XMLAuthenticationResult(AuthenticationResultStatus::OK);
			$result->setRoles($userRoles);
			$result->setUserID($userID);
			return $result;
		}
	}
	
	/**
	 * Performs a logout operation:
	 * - removes user id from persistence drivers (if any)
	 *
	 * @return XMLAuthenticationResult
	 */
	public function logout() {
		// detect user_id from persistence drivers
		$userID = null;
		foreach($this->persistenceDrivers as $persistentDriver) {
			$userID = $persistentDriver->load();
			if($userID) break;
		}
		if(!$userID) {
			$result = new AuthenticationResult(AuthenticationResultStatus::LOGOUT_FAILED);
			return $result;
		} else {
			// clears data from persistence drivers
			foreach($this->persistenceDrivers as $persistentDriver) {
				$persistentDriver->clear($userID);
			}
			
			// returns result
			$result = new AuthenticationResult(AuthenticationResultStatus::OK);
			return $result;
		}
	}
}