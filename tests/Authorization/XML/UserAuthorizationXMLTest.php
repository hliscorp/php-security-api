<?php
namespace Test\Lucinda\WebSecurity\Authorization\XML;
    
use Lucinda\WebSecurity\Authorization\XML\UserAuthorizationXML;
use Lucinda\UnitTest\Result;

class UserAuthorizationXMLTest
{

    public function getRoles()
    {
        $xml = \simplexml_load_string('
<xml>
    <users roles="GUEST">
        <user id="1" roles="USER"/>
    </users>
</xml>
');
        $object = new UserAuthorizationXML($xml);
        
        $results = [];
        $results[] = new Result($object->getRoles(null)==["GUEST"], "checks user without roles");
        $results[] = new Result($object->getRoles(1)==["USER"], "checks user without roles");
        return $results;
    }
        

}
