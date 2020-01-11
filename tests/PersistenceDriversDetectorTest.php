<?php
namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\PersistenceDriversDetector;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver as RememberMePersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver as SessionPersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Token\JsonWebTokenPersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;

class PersistenceDriversDetectorTest
{
    private $xml;
    
    public function __construct()
    {
        $salt = (new SaltGenerator(10))->getSalt();
        $this->xml = \simplexml_load_string('
<security>
    <persistence>
        <session/>
        <remember_me secret="'.$salt.'"/>
        <synchronizer_token secret="'.$salt.'"/>
        <json_web_token secret="'.$salt.'"/>
    </persistence>
</security>
');
    }

    public function getPersistenceDrivers()
    {
        $pdd = new PersistenceDriversDetector($this->xml, "127,0.0.1");
        $persistenceDrivers = $pdd->getPersistenceDrivers();
        $results = [];
        $results[] = new Result($persistenceDrivers[0] instanceof SessionPersistenceDriver, "tested session");
        $results[] = new Result($persistenceDrivers[1] instanceof RememberMePersistenceDriver, "tested remember me");
        $results[] = new Result($persistenceDrivers[2] instanceof SynchronizerTokenPersistenceDriver, "tested synchronizer token");
        $results[] = new Result($persistenceDrivers[3] instanceof JsonWebTokenPersistenceDriver, "tested json web token");
        return $results;
    }
}
