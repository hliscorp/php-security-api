<?php
namespace Test\Lucinda\WebSecurity\Authentication\OAuth2;
    
use Lucinda\WebSecurity\Authentication\OAuth2\XMLParser;
use Lucinda\UnitTest\Result;

class XMLParserTest
{
    private $parser;
    
    public function __construct()
    {
        $xml = simplexml_load_string('
<security>
    <authentication>
        <oauth2/>
    </authentication>
</security>');  
        $this->parser = new XMLParser($xml);
    }

    public function getLoginCallback()
    {
        return new Result($this->parser->getLoginCallback()=="login");
    }
        

    public function getLogoutCallback()
    {
        return new Result($this->parser->getLogoutCallback()=="logout");
    }
        

    public function getTargetCallback()
    {
        return new Result($this->parser->getTargetCallback()=="index");
    }
        

}
