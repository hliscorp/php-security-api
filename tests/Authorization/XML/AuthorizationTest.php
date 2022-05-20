<?php

namespace Test\Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\Authorization\XML\Authorization;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authorization\ResultStatus;
use Lucinda\WebSecurity\Authorization\XML\UserAuthorizationXML;
use Lucinda\WebSecurity\Authorization\Result as AuthorizationResult;

class AuthorizationTest
{
    private $xml;

    public function __construct()
    {
        $this->xml = \simplexml_load_string('
<xml>
    <users roles="GUEST">
        <user id="1" roles="USER"/>
    </users>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>');
    }

    public function authorize()
    {
        $authorization = new Authorization("login", "index");
        $results = [];
        $results[] = new Result($this->test($authorization, "asdf", null)->getStatus()==ResultStatus::NOT_FOUND, "test path not found");
        $results[] = new Result($this->test($authorization, "login", null)->getStatus()==ResultStatus::OK, "guest allowed to login");
        $results[] = new Result($this->test($authorization, "index", null)->getStatus()==ResultStatus::UNAUTHORIZED, "guest unauthorized to index");
        $results[] = new Result($this->test($authorization, "index", 1)->getStatus()==ResultStatus::OK, "user allowed to index");
        $results[] = new Result($this->test($authorization, "administration", 1)->getStatus()==ResultStatus::FORBIDDEN, "user forbidden to administration");
        return $results;
    }

    private function test(Authorization $authorization, string $url, ?int $userID): AuthorizationResult
    {
        return $authorization->authorize($this->xml, $url, $userID, new UserAuthorizationXML($this->xml));
    }
}
