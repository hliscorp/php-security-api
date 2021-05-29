<?php
namespace Test\Lucinda\WebSecurity\Authorization\DAO;

use Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO;
use Lucinda\WebSecurity\Authorization\DAO\Authorization;
use Lucinda\WebSecurity\Authorization\Result as AuthorizationResult;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authorization\ResultStatus;

class AuthorizationTest
{
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
        return $authorization->authorize(new MockPageAuthorizationDAO($url), new MockUserAuthorizationDAO($userID), "GET");
    }
}
