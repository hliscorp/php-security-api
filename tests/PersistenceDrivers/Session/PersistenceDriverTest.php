<?php

namespace Test\Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\Session\PersistenceDriver;
use Lucinda\UnitTest\Result;

class PersistenceDriverTest
{
    private $object;

    public function __construct()
    {
        $securityOptions = new CookieSecurityOptions();
        $securityOptions->setExpirationTime(3600);
        $this->object = new PersistenceDriver(
            "uid",
            $securityOptions,
            "192.168.1.9"
        );
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
