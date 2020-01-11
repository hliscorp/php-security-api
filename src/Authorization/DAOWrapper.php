<?php
namespace Lucinda\WebSecurity\Authorization;

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\ClassFinder;
use Lucinda\WebSecurity\ConfigurationException;
use Lucinda\WebSecurity\Authorization\DAO\UserAuthorizationDAO;
use Lucinda\WebSecurity\Authorization\DAO\PageAuthorizationDAO;
use Lucinda\WebSecurity\Authorization\DAO\Authorization;

/**
 * Binds DAOAuthorization @ SECURITY-API to settings from configuration.xml @ SERVLETS-API then performs request authorization via database.
 */
class DAOWrapper extends Wrapper
{
    const DEFAULT_LOGGED_IN_PAGE = "index";
    const DEFAULT_LOGGED_OUT_PAGE = "login";
    
    /**
     * Creates an object
     *
     * @param \SimpleXMLElement $xml Contents of security.authorization.by_dao tag @ configuration.xml
     * @param Request $request Encapsulated request made by client
     * @param mixed $userID Unique user identifier (usually an integer)
     * @throws ConfigurationException If resources referenced in XML do not exist or do not extend/implement required blueprint.
     */
    public function __construct(\SimpleXMLElement $xml, Request $request, $userID)
    {
        // create dao object
        $xmlTag = $xml->authorization->by_dao;
        
        // detects logged in callback to use if authorization fails
        $loggedInCallback = (string) $xmlTag["logged_in_callback"];
        if (!$loggedInCallback) {
            $loggedInCallback = self::DEFAULT_LOGGED_IN_PAGE;
        }
        
        // detects logged out callback to use if authorization fails
        $loggedOutCallback = (string) $xmlTag["logged_out_callback"];
        if (!$loggedOutCallback) {
            $loggedOutCallback = self::DEFAULT_LOGGED_OUT_PAGE;
        }
        
        // loads and instances page DAO object
        $pageDAO = $this->getPageDAO($xml, $request->getUri());

        // loads and instances user DAO object
        $userDAO = $this->getUserDAO($xml, $userID);        

        // performs authorization
        $authorization = new Authorization($loggedInCallback, $loggedOutCallback);
        $this->setResult($authorization->authorize($pageDAO, $userDAO, $request->getMethod()));
    }
    
    /**
     * Gets DAO where page rights are checked
     * 
     * @param \SimpleXMLElement $xml
     * @param string $pageUrl
     * @throws ConfigurationException
     * @return PageAuthorizationDAO
     */
    private function getPageDAO(\SimpleXMLElement $xml, string $pageUrl): PageAuthorizationDAO
    {
        $classFinder = new ClassFinder((string) $xml["dao_path"]);
        $className = $classFinder->find((string) $xml->authorization->by_dao["page_dao"]);
        $pageDAO = new $className($pageUrl);
        if (!($pageDAO instanceof PageAuthorizationDAO)) {
            throw new  ConfigurationException("Class must be instance of PageAuthorizationDAO!");
        }
        return $pageDAO;
    }
    
    /**
     * Gets DAO where user rights are checked 
     * 
     * @param \SimpleXMLElement $xml
     * @param mixed $userID
     * @throws ConfigurationException
     * @return UserAuthorizationDAO
     */
    private function getUserDAO(\SimpleXMLElement $xml, $userID): UserAuthorizationDAO
    {
        $classFinder = new ClassFinder((string) $xml["dao_path"]);
        $className = $classFinder->find((string) $xml->authorization->by_dao["user_dao"]);
        $userDAO = new $className($userID);
        if (!($userDAO instanceof UserAuthorizationDAO)) {
            throw new  ConfigurationException("Class must be instance of UserAuthorizationDAO!");
        }
        return $userDAO;
    }
}
