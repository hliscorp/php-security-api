<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;

class SaltGeneratorTest
{
    public function getSalt()
    {
        $object = new SaltGenerator(12);
        return new Result(strlen($object->getSalt())==12);
    }
}
