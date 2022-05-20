<?php

namespace Test\Lucinda\WebSecurity\Authentication\XML;

use Lucinda\WebSecurity\Authentication\XML\UserAuthenticationXML;
use Lucinda\UnitTest\Result;

class UserAuthenticationXMLTest
{
    public function login()
    {
        $xml = simplexml_load_string('
<security>
    <users>
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'"/>
    </users>
</security>');
        $object = new UserAuthenticationXML($xml);

        $results = [];
        $results[] = new Result($object->login("test", "me1")===null, "tested failed login");
        $results[] = new Result($object->login("test", "me")==1, "tested successful login");
        return $results;
    }
}
