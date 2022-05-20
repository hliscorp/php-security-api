<?php

namespace Test\Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\Authentication\OAuth2\Exception;
use Lucinda\UnitTest\Result;

class ExceptionTest
{
    private $object;

    public function __construct()
    {
        $this->object = new Exception("asd");
    }

    public function setErrorCode()
    {
        $this->object->setErrorCode("some code");
        return new Result(true);
    }


    public function getErrorCode()
    {
        return new Result($this->object->getErrorCode()=="some code");
    }


    public function setErrorDescription()
    {
        $this->object->setErrorDescription("some description");
        return new Result(true);
    }


    public function getErrorDescription()
    {
        return new Result($this->object->getErrorDescription()=="some description");
    }
}
