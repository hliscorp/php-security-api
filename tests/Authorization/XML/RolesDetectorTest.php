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
        <route url="login" roles="GUEST,USER"/>
        <route url="index" roles="USER"/>
        <route url="logout" roles="USER,ADMINISTRATOR"/>
        <route url="admin" roles="ADMINISTRATOR"/>
    </routes>
</xml>
');
        $results = [];
        
        $object = new RolesDetector($xml, "routes", "route", "url", "asdf");
        $results[] = new Result($object->getRoles()==[], "checks element without roles");
        
        $object = new RolesDetector($xml, "routes", "route", "url", "login");
        $results[] = new Result($object->getRoles("login")==["GUEST","USER"], "checks element without roles");
        
        return $results;
    }
        

}
