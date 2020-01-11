<?php
namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Session;
    
use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver;
use Lucinda\UnitTest\Result;

class PersistenceDriverTest
{
    private $object;
    
    public function __construct()
    {
        $this->object = new PersistenceDriver("uid", 3600, false, false, "192.168.1.9");
    }
    
    
    public function save()
    {
        session_start();
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
