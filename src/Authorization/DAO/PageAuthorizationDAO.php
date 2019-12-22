<?php
namespace Lucinda\WebSecurity\Authorization\DAO;


/**
 * Defines blueprints for a DAO that checks requested page access levels in database.
 */
abstract class PageAuthorizationDAO
{
    protected $pageID;

    /**
     * Saves detected database ID of page requested
     *
     * @param string $pageURL URL of page requested
     */
    public function __construct(string $pageURL)
    {
        $this->pageID = $this->detectID($pageURL);
    }

    /**
     * Detects database ID of page requested.
     *
     * @param string $pageURL URL of page requested
     * @return integer
     */
    abstract protected function detectID(string $pageURL): int;

    /**
     * Checks if current page does not require being logged in based on detected ID.
     *
     * @return boolean
     */
    abstract public function isPublic(): bool;
    
    /**
     * Gets detected id of page requested
     *
     * @return integer
     */
    public function getID(): int
    {
        return $this->pageID;
    }
}
