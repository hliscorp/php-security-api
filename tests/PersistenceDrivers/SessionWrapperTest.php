<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\PersistenceDrivers\SessionWrapper;
use Lucinda\UnitTest\Result;

class SessionWrapperTest
{
    private $xml;
    
    public function __construct()
    {
        $this->xml = \simplexml_load_string('
<session/>
');
    }
    
    public function getDriver()
    {
        $driver = new SessionWrapper($this->xml, "127.0.0.1");
        $driver->getDriver()->save(1);
        return new Result($driver->getDriver()->load()==1);
    }
}
