<?php

namespace Test\Lucinda\WebSecurity\Token;

use Lucinda\WebSecurity\Token\Encryption;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;

class EncryptionTest
{
    private $object;
    private $value;

    public function __construct()
    {
        $this->object = new Encryption((new SaltGenerator(12))->getSalt());
    }

    public function encrypt()
    {
        $this->value = $this->object->encrypt("asdfgh");
        return new Result($this->value ? true : false);
    }


    public function decrypt()
    {
        return new Result($this->object->decrypt($this->value)=="asdfgh" ? true : false);
    }
}
