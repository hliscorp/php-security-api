<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\Request;
use Lucinda\UnitTest\Result;

class RequestTest
{
    private $object;

    public function __construct()
    {
        $this->object = new Request();
    }


    public function setUri()
    {
        $this->object->setUri("login");
        return new Result(true);
    }


    public function setContextPath()
    {
        $this->object->setContextPath("test");
        return new Result(true);
    }


    public function setIpAddress()
    {
        $this->object->setIpAddress("127.0.0.1");
        return new Result(true);
    }


    public function setMethod()
    {
        $this->object->setMethod("POST");
        return new Result(true);
    }


    public function setParameters()
    {
        $this->object->setParameters(["username"=>"test", "password"=>"me"]);
        return new Result(true);
    }


    public function setAccessToken()
    {
        $this->object->setAccessToken("qwerty");
        return new Result(true);
    }

    public function getUri()
    {
        return new Result($this->object->getUri()=="login");
    }


    public function getContextPath()
    {
        return new Result($this->object->getContextPath()=="test");
    }


    public function getIpAddress()
    {
        return new Result($this->object->getIpAddress()=="127.0.0.1");
    }


    public function getMethod()
    {
        return new Result($this->object->getMethod()=="POST");
    }


    public function getParameters()
    {
        return new Result($this->object->getParameters()==["username"=>"test", "password"=>"me"]);
    }


    public function getAccessToken()
    {
        return new Result($this->object->getAccessToken()=="qwerty");
    }
}
