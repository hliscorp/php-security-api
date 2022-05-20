<?php

namespace Test\Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\Authorization\XML\RolesDetector;
use Lucinda\UnitTest\Result;

class RolesDetectorTest
{
    public function getRoles()
    {
        $xml = \simplexml_load_string('
<xml>
    <routes roles="USER">
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="admin" roles="ADMINISTRATOR"/>
    </routes>
</xml>
');
        $results = [];

        $object = new RolesDetector($xml, "routes", "route", "id", "asdf");
        $results[] = new Result($object->getRoles()==[], "checks element without roles");

        $object = new RolesDetector($xml, "routes", "route", "id", "login");
        $results[] = new Result($object->getRoles("login")==["GUEST","USER"], "checks element without roles");

        return $results;
    }
}
