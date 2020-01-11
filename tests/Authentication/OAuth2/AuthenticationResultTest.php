<?php
namespace Test\Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\Authentication\OAuth2\AuthenticationResult;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;

class AuthenticationResultTest
{
    private $object;
    
    public function __construct()
    {
        $this->object = new AuthenticationResult(ResultStatus::LOGIN_OK);
    }
    
    
    public function setAccessToken()
    {
        $this->object->setAccessToken("qwerty");
        return new Result(true);
    }
        

    public function getAccessToken()
    {
        return new Result($this->object->getAccessToken()=="qwerty");
    }
        

    public function getStatus()
    {
        return new Result($this->object->getStatus()==ResultStatus::LOGIN_OK);
    }
        

    public function setCallbackURI()
    {
        $this->object->setCallbackURI("foo/bar");
        return new Result(true);
    }
        

    public function getCallbackURI()
    {
        return new Result($this->object->getCallbackURI()=="foo/bar");
    }
        

    public function setUserID()
    {
        $this->object->setUserID(1);
        return new Result(true);
    }
        

    public function getUserID()
    {
        return new Result($this->object->getUserID()==1);
    }
        

    public function setTimePenalty()
    {
        $this->object->setTimePenalty(1);
        return new Result(true);
    }
        

    public function getTimePenalty()
    {
        return new Result($this->object->getTimePenalty()==1);
    }
}
