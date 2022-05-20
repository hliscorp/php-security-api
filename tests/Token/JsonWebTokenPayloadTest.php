<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\JsonWebTokenPayload;
use Lucinda\UnitTest\Result;

class JsonWebTokenPayloadTest
{
    private $object;

    public function __construct()
    {
        $this->object = new JsonWebTokenPayload();
    }

    public function setIssuer()
    {
        $this->object->setIssuer("qwerty");
        return new Result(true);
    }


    public function getIssuer()
    {
        return new Result($this->object->getIssuer()=="qwerty");
    }


    public function setSubject()
    {
        $this->object->setSubject(1);
        return new Result(true);
    }


    public function getSubject()
    {
        return new Result($this->object->getSubject()==1);
    }


    public function setAudience()
    {
        $this->object->setAudience("uiop");
        return new Result(true);
    }


    public function getAudience()
    {
        return new Result($this->object->getAudience()=="uiop");
    }


    public function setEndTime()
    {
        $this->object->setEndTime(123);
        return new Result(true);
    }


    public function getEndTime()
    {
        return new Result($this->object->getEndTime()==123);
    }


    public function setStartTime()
    {
        $this->object->setStartTime(456);
        return new Result(true);
    }


    public function getStartTime()
    {
        return new Result($this->object->getStartTime()==456);
    }


    public function setIssuedTime()
    {
        $this->object->setIssuedTime(789);
        return new Result(true);
    }


    public function getIssuedTime()
    {
        return new Result($this->object->getIssuedTime()==789);
    }


    public function setApplicationId()
    {
        $this->object->setApplicationId("zxcvb");
        return new Result(true);
    }


    public function getApplicationId()
    {
        return new Result($this->object->getApplicationId()=="zxcvb");
    }


    public function setCustomClaim()
    {
        $this->object->setCustomClaim("x", "y");
        return new Result(true);
    }


    public function getCustomClaim()
    {
        return new Result($this->object->getCustomClaim("x")=="y");
    }


    public function toArray()
    {
        $data = ["iss"=>"a", "sub"=>"b", "aud"=>"c"];
        $object = new JsonWebTokenPayload($data);
        return new Result($object->toArray()==$data);
    }
}
