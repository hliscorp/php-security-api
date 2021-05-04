<?php
namespace Test\Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\CsrfTokenDetector;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Authentication\OAuth2Wrapper;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\ResultStatus;
use Lucinda\WebSecurity\Token\Exception as TokenException;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockOauth2Driver;

class OAuth2WrapperTest
{
    private $xml;
    private $persistenceDriver;
    private $oauth2Driver;
    private $csrfTokenDetector;
    
    public function __construct()
    {
        $secret = (new SaltGenerator(10))->getSalt();
        $this->xml = simplexml_load_string('
<security>
    <csrf secret="'.$secret.'"/>
    <authentication>
        <oauth2 dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockVendorAuthenticationDAO"/>
    </authentication>
</security>');
        $this->persistenceDriver = new SynchronizerTokenPersistenceDriver($secret, "127.0.0.1");
        $this->oauth2Driver = new MockOauth2Driver("Facebook");
        $this->csrfTokenDetector = new CsrfTokenDetector($this->xml, "127.0.0.1");
    }
    
    public function getResult()
    {
        $results = [];
        
        $request = new Request();
        
        $request->setUri("asd");
        $wrapper = new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
        $results[] = new Result($wrapper->getResult()===null, "tested no login");
        
        $request->setUri("login/facebook");
        $wrapper = new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
        $results[] = new Result($wrapper->getResult()->getStatus()==ResultStatus::DEFERRED, "tested login - authorization code");
        
        $request->setParameters(["code"=>"qwerty"]);
        try {
            new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
            $results[] = new Result(false, "tested login + authorization code: missing csrf token");
        } catch (TokenException $e) {
            $results[] = new Result($e->getMessage()=="CSRF token is invalid or missing!", "tested login + authorization code: missing csrf token");
        }
        
        $request->setParameters(["code"=>"qwerty", "state"=>$this->csrfTokenDetector->generate(0)]);
        $wrapper = new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
        $results[] = new Result($wrapper->getResult()->getStatus()==ResultStatus::LOGIN_OK, "tested login + authorization code: successful");
        
        $request->setUri("logout");
        $wrapper = new OAuth2Wrapper($this->xml, $request, $this->csrfTokenDetector, [$this->persistenceDriver], [$this->oauth2Driver]);
        $results[] = new Result($wrapper->getResult()->getStatus()==ResultStatus::LOGOUT_OK, "tested logout: status");
        $results[] = new Result($this->persistenceDriver->load()==null, "tested logout: persistence");
        
        return $results;
    }
}
