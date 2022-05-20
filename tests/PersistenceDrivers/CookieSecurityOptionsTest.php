<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;

class CookieSecurityOptionsTest
{
    private CookieSecurityOptions $options;

    public function __construct()
    {
        $this->options = new CookieSecurityOptions();
    }

    public function setExpirationTime()
    {
        $this->options->setExpirationTime(1);
        return new Result(true, "tested via getExpirationTime()");
    }

    public function getExpirationTime()
    {
        return new Result($this->options->getExpirationTime()==1);
    }


    public function setIsHttpOnly()
    {
        $this->options->setIsHttpOnly(true);
        return new Result(true, "tested via isHttpOnly()");
    }


    public function isHttpOnly()
    {
        return new Result($this->options->isHttpOnly());
    }


    public function setIsSecure()
    {
        $this->options->setIsSecure(true);
        return new Result(true, "tested via isSecure()");
    }


    public function isSecure()
    {
        return new Result($this->options->isSecure());
    }
}
