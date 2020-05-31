<?php
namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\ClassFinder;
use Lucinda\UnitTest\Result;

class ClassFinderTest
{
    public function find()
    {
        $className = "Test\Lucinda\WebSecurity\Authentication\MockUsersAuthentication";
        $finder = new ClassFinder(__DIR__."/Authentication");
        return new Result($finder->find($className)==$className);
    }
}
