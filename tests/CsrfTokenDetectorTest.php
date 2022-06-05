<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\UnitTest\Result;

class CsrfTokenDetectorTest
{
    private $xml;

    public function __construct()
    {
        $this->xml = \simplexml_load_string(
            '
<security>
    <csrf secret="'.(new SaltGenerator(10))->getSalt().'"/>
</security>
'
        );
    }

    public function generate()
    {
        $this->object = new CsrfTokenDetector($this->xml, "127.0.0.1");
        return new Result(strlen($this->object->generate(0))==180);
    }


    public function isValid()
    {
        $userID = 0;
        $this->object = new CsrfTokenDetector($this->xml, "127.0.0.1");
        $token = $this->object->generate($userID);
        return new Result($this->object->isValid($token, $userID));
    }
}
