<?php
namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Authentication\Form\FormRequestValidator;
use Lucinda\WebSecurity\Request;
use Lucinda\UnitTest\Result;

class FormRequestValidatorTest
{
    private $xml;
    
    public function __construct()
    {
        $this->xml = simplexml_load_string('
<security>
    <authentication>
        <form/>
    </authentication>
</security>');
    }
    

    public function login()
    {
        $result = [];
        
        $request = new Request();
        
        $request->setUri("asdf");
        $request->setMethod("GET");
        $validator = new FormRequestValidator($this->xml, $request);
        $login = $validator->login();
        $result[] = new Result($login==null, "check not login");
        
        $request->setUri("login");
        $request->setMethod("POST");
        $request->setParameters(["username"=>"test", "password"=>"me"]);
        $validator = new FormRequestValidator($this->xml, $request);
        $login = $validator->login();
        $result[] = new Result($login->getDestinationPage()=="index", "check login");
        
        return $result;
    }
        

    public function logout()
    {
        $result = [];
        
        $request = new Request();
        
        $request->setUri("asdf");
        $validator = new FormRequestValidator($this->xml, $request);
        $logout = $validator->logout();
        $result[] = new Result($logout==null, "check not logout");
        
        $request->setUri("logout");
        $validator = new FormRequestValidator($this->xml, $request);
        $logout = $validator->logout();
        $result[] = new Result($logout->getDestinationPage()=="login", "check logout");
        
        return $result;
    }
}
