<?php
namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\SecurityPacket;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;

class SecurityPacketTest
{
    private $object;
    
    public function __construct()
    {
        $this->object = new SecurityPacket("test");
    }
    
    public function setCallback()
    {
        $this->object->setCallback("index");
        return new Result(true);
    }
        

    public function getCallback()
    {
        return new Result($this->object->getCallback()=="index");
    }
        

    public function setStatus()
    {
        $this->object->setStatus(ResultStatus::LOGIN_OK);
        return new Result(true);
    }
        

    public function getStatus()
    {
        return new Result($this->object->getStatus()=="login_ok");
    }
        

    public function setAccessToken()
    {
        $persistenceDriver = new SynchronizerTokenPersistenceDriver((new SaltGenerator(10))->getSalt(), "127.0.0.1");
        $persistenceDriver->save(1);
        $this->object->setAccessToken(1, [$persistenceDriver]);
        return new Result(true);
    }
        

    public function getAccessToken()
    {
        return new Result($this->object->getAccessToken()?true:false);
    }
        

    public function setTimePenalty()
    {
        $this->object->setTimePenalty(1);
        return new Result(true);
    }
        

    public function getTimePenalty()
    {
        return new Result($this->object->getTimePenalty()==1);
    }
}
