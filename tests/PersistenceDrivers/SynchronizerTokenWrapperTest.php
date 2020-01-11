<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers;
    
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerTokenWrapper;
use Lucinda\UnitTest\Result;

class SynchronizerTokenWrapperTest
{
    private $xml;
    
    public function __construct()
    {
        $this->xml = \simplexml_load_string('
<synchronizer_token secret="'.(new SaltGenerator(10))->getSalt().'" expiration="2" regeneration="1"/>
');
    }
    
    public function getDriver()
    {
        $results = [];
        $driver = new SynchronizerTokenWrapper($this->xml, "127.0.0.1");
        $driver->getDriver()->save(1);
        $results[] = new Result($driver->getDriver()->load()==1);
        sleep(1);
        $results[] = new Result($driver->getDriver()->load()==1);
        sleep(2);
        $results[] = new Result(!$driver->getDriver()->load());
        return $results;
    }

}
