<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Token;

use Lucinda\WebSecurity\PersistenceDrivers\Token\JsonWebTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;

class JsonWebTokenPersistenceDriverTest
{
    private $object;
    
    public function __construct()
    {
        $this->object = new JsonWebTokenPersistenceDriver((new SaltGenerator(10))->getSalt());
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
