<?php
namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;

class SynchronizerTokenTest
{
    private $object;
    private $value;
    
    public function __construct()
    {
        $this->object = new SynchronizerToken("127.0.0.1", (new SaltGenerator(12))->getSalt());
    }
    
    public function encode()
    {
        $this->value = $this->object->encode(1);
        return new Result(true);
    }
        

    public function decode()
    {
        return new Result($this->object->decode($this->value)==1);
    }
}
