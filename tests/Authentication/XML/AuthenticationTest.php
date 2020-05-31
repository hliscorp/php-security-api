<?php
namespace Test\Lucinda\WebSecurity\Authentication\XML;

use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\Authentication\XML\Authentication;

class AuthenticationTest
{
    private $xml;
    private $persistenceDriver;
    
    public function __construct()
    {
        $this->xml = simplexml_load_string('
<security>
    <users>
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'"/>
    </users>
</security>');
        $this->persistenceDriver = new SynchronizerTokenPersistenceDriver((new SaltGenerator(10))->getSalt(), "127.0.0.1");
    }

    public function login()
    {
        $results = [];
        $object = new Authentication($this->xml, [$this->persistenceDriver]);
        $results[] = new Result($object->login("test", "m1e")->getStatus()==ResultStatus::LOGIN_FAILED, "tested failed login");
        $results[] = new Result($object->login("test", "me")->getStatus()==ResultStatus::LOGIN_OK, "tested successful login");
        $results[] = new Result($this->persistenceDriver->load()==1, "tested login persistence");
        return $results;
    }
        

    public function logout()
    {
        $object = new Authentication($this->xml, [$this->persistenceDriver]);
        $results = [];
        $results[] = new Result($object->logout()->getStatus()==ResultStatus::LOGOUT_OK, "tested successful logout");
        $results[] = new Result($this->persistenceDriver->load()==null, "tested logout persistence");
        $results[] = new Result($object->logout()->getStatus()==ResultStatus::LOGOUT_FAILED, "tested failed logout");
        return $results;
    }
}
