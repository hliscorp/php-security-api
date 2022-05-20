<?php

namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Authentication\Form\LoginRequest;
use Lucinda\UnitTest\Result;

class LoginRequestTest
{
    private $object;

    public function __construct()
    {
        $this->object = new LoginRequest();
    }

    public function setUsername()
    {
        $this->object->setUsername("test");
        return new Result(true);
    }


    public function setPassword()
    {
        $this->object->setPassword("me");
        return new Result(true);
    }


    public function setRememberMe()
    {
        $this->object->setRememberMe(true);
        return new Result(true);
    }


    public function setSourcePage()
    {
        $this->object->setSourcePage("login");
        return new Result(true);
    }


    public function setDestinationPage()
    {
        $this->object->setDestinationPage("index");
        return new Result(true);
    }


    public function getUsername()
    {
        return new Result($this->object->getUsername() == "test");
    }


    public function getPassword()
    {
        return new Result($this->object->getPassword() == "me");
    }


    public function isRememberMe()
    {
        return new Result($this->object->isRememberMe() === true);
    }


    public function getSourcePage()
    {
        return new Result($this->object->getSourcePage() == "login");
    }


    public function getDestinationPage()
    {
        return new Result($this->object->getDestinationPage() == "index");
    }
}
