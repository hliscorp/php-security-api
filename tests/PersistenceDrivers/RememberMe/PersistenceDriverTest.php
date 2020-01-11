<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers\RememberMe;
    
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;

class PersistenceDriverTest
{
    private $object;
    
    public function __construct()
    {
        $this->object = new PersistenceDriver((new SaltGenerator(10))->getSalt(), "remember_me", 3600, false, false, "192.168.1.9");
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
        

}
