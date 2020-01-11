<?php
namespace Test\Lucinda\WebSecurity\Authentication\Form;
    
use Lucinda\WebSecurity\Authentication\Form\LogoutRequest;
use Lucinda\UnitTest\Result;

class LogoutRequestTest
{
    private $object;
    
    public function __construct()
    {
        $this->object = new LogoutRequest();
    }

    public function setSourcePage()
    {
        $this->object->setSourcePage("logout");
        return new Result(true);
    }
        

    public function setDestinationPage()
    {
        $this->object->setDestinationPage("index");
        return new Result(true);
    }
        

    public function getSourcePage()
    {
        return new Result($this->object->getSourcePage() == "logout");
    }
        

    public function getDestinationPage()
    {
        return new Result($this->object->getDestinationPage() == "index");
    }
        

}
