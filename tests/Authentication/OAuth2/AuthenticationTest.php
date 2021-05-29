<?php
namespace Test\Lucinda\WebSecurity\Authentication\OAuth2;

use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\Authentication\OAuth2\Authentication;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockVendorAuthenticationDAO;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockOauth2Driver;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;

class AuthenticationTest
{
    private $dao;
    private $persistenceDriver;
    
    public function __construct()
    {
        $this->dao = new MockVendorAuthenticationDAO();
        $this->persistenceDriver = new SynchronizerTokenPersistenceDriver((new SaltGenerator(10))->getSalt(), "127.0.0.1");
    }

    public function login()
    {
        $results = [];
        $object = new Authentication($this->dao, [$this->persistenceDriver]);
        $results[] = new Result($object->login(new MockOauth2Driver("Google"), "qwerty")->getStatus()==ResultStatus::LOGIN_FAILED, "tested failed login");
        $results[] = new Result($object->login(new MockOauth2Driver("Facebook"), "qwerty")->getStatus()==ResultStatus::LOGIN_OK, "tested successful login");
        $results[] = new Result($object->login(new MockOauth2Driver("Facebook"), "qwerty")->getAccessToken()=="asdfgh", "tested access token");
        $results[] = new Result($this->persistenceDriver->load()==1, "tested login persistence");
        return $results;
    }
        

    public function logout()
    {
        $results = [];
        $object = new Authentication($this->dao, [$this->persistenceDriver]);
        $results[] = new Result($object->logout()->getStatus()==ResultStatus::LOGOUT_OK, "tested successful logout");
        $results[] = new Result($this->persistenceDriver->load()==null, "tested logout persistence");
        $results[] = new Result($object->logout()->getStatus()==ResultStatus::LOGOUT_FAILED, "tested failed logout");
        return $results;
    }
}
