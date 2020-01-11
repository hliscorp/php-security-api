<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Token;
    
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;

class SynchronizerTokenPersistenceDriverTest
{
    private $object;
    private $salt;
    
    public function __construct()
    {
        $this->salt = (new SaltGenerator(10))->getSalt();
        $this->object = new SynchronizerTokenPersistenceDriver($this->salt, "127.0.0.1");
    }
    
    public function save()
    {
        $this->object->save(1);
        return new Result(true);
    }
    
    public function load()
    {
        return new Result($this->object->load()==1);
    }
    
    
    public function clear()
    {
        $this->object->clear();
        return new Result(!$this->object->load());
    }
    
    
    public function setAccessToken()
    {
        $this->object->setAccessToken("qwerty");
        return new Result(true);
    }
    
    
    public function getAccessToken()
    {
        return new Result($this->object->getAccessToken()=="qwerty");
    }
}
