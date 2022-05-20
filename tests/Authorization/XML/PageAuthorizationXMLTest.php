<?php

namespace Test\Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\Authorization\XML\PageAuthorizationXML;
use Lucinda\UnitTest\Result;

class PageAuthorizationXMLTest
{
    public function getRoles()
    {
        $xml = \simplexml_load_string('
<xml>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="admin" roles="ADMINISTRATOR"/>
    </routes>
</xml>
');
        $object = new PageAuthorizationXML($xml);

        $results = [];
        $results[] = new Result($object->getRoles("asdf")==[], "checks route without roles");
        $results[] = new Result($object->getRoles("login")==["GUEST","USER"], "checks route without roles");
        return $results;
    }
}
