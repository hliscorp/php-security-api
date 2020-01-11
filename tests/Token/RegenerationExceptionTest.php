<?php
namespace Test\Lucinda\WebSecurity\Token;
    
use Lucinda\WebSecurity\Token\RegenerationException;
use Lucinda\UnitTest\Result;

class RegenerationExceptionTest
{
    private $object;
    
    public function __construct()
    {
        $this->object = new RegenerationException();
    }

    public function setPayload()
    {
        $this->object->setPayload("asdfgh");
        return new Result(true);
    }
        

    public function getPayload()
    {
        return new Result($this->object->getPayload()=="asdfgh");
    }
        

}
