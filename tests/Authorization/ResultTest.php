<?php
namespace Test\Lucinda\WebSecurity\Authorization;

use Lucinda\WebSecurity\Authorization\Result as AuthorizationResult;
use Lucinda\WebSecurity\Authorization\ResultStatus;
use Lucinda\UnitTest\Result;

class ResultTest
{
    private $object;
    
    public function __construct()
    {
        $this->object = new AuthorizationResult(ResultStatus::FORBIDDEN, "index");
    }

    public function getStatus()
    {
        return new Result($this->object->getStatus()==ResultStatus::FORBIDDEN);
    }
        

    public function getCallbackURI()
    {
        return new Result($this->object->getCallbackURI()=="index");
    }
}
