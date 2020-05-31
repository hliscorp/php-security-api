<?php
namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\JsonWebToken;
use Lucinda\WebSecurity\Token\JsonWebTokenPayload;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Token\SaltGenerator;

class JsonWebTokenTest
{
    private $object;
    private $value;
    
    public function __construct()
    {
        $this->object = new JsonWebToken((new SaltGenerator(12))->getSalt());
    }

    public function encode()
    {
        $payload = new JsonWebTokenPayload();
        $payload->setApplicationId(123);
        $this->value = $this->object->encode($payload);
        return new Result($this->value?true:false);
    }
        

    public function decode()
    {
        $payload = new JsonWebTokenPayload();
        $payload->setApplicationId(123);
        return new Result($this->object->decode($this->value)==$payload?true:false);
    }
}
