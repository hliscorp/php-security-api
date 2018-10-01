<?php
namespace Lucinda\WebSecurity;

/**
 * Defines blueprints for a DAO that checks requested page access levels in database.
 */
abstract class PageAuthorizationDAO {
    protected $pageID;

    public function __construct($pageURL) {
        $this->pageID = $this->detectID($pageURL);
    }

    /**
     * Detects database ID of page requested.
     *
     * @param string $pageURL URL of page requested
     * @return integer
     */
    abstract protected function detectID($pageURL);

	/**
	 * Checks if current page does not require being logged in based on detected ID.
	 * 
	 * @return boolean
	 */
    abstract public function isPublic();
    
    /**
     * Gets detected id of page requested
     * 
     * @return integer
     */
    public function getID() {
        return $this->pageID;
    }
}