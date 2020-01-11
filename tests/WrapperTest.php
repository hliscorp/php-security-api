<?php
namespace Test\Lucinda\WebSecurity;
    
use Lucinda\WebSecurity\Token\SaltGenerator;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Wrapper;
use Lucinda\WebSecurity\SecurityPacket;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\OAuth2\Exception as OAuth2Exception;
use Test\Lucinda\WebSecurity\Authentication\MockOauth2Driver;

class WrapperTest
{
    private $xml_dao_dao;
    private $xml_dao_xml;
    private $xml_xml_dao;
    private $xml_xml_xml;
    private $xml_oauth2_dao;
    private $xml_oauth2_xml;
    
    public function __construct()
    {
        // TODO: test full xmls
        
        $secret = (new SaltGenerator(10))->getSalt();
        $this->xml_dao_dao = \simplexml_load_string('
<xml>
    <security dao_path="'.__DIR__.'">
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <form dao="Authentication/'.__NAMESPACE__.'\\Authentication\\MockUsersAuthentication" throttler="Authentication/'.__NAMESPACE__.'\\Authentication\\MockLoginThrottler"/>
        </authentication>
        <authorization>
            <by_dao page_dao="Authorization/'.__NAMESPACE__.'\\Authorization\\MockPageAuthorizationDAO" user_dao="Authorization/'.__NAMESPACE__.'\\Authorization\\MockUserAuthorizationDAO"/>
        </authorization>
    </security>
</xml>
');
        $this->xml_dao_xml = \simplexml_load_string('
<xml>
    <security dao_path="'.__DIR__.'">
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <form dao="Authentication/'.__NAMESPACE__.'\\Authentication\\MockUsersAuthentication" throttler="Authentication/'.__NAMESPACE__.'\\Authentication\\MockLoginThrottler"/>
        </authentication>
        <authorization>
            <by_route/>
        </authorization>
    </security>
    <routes>
        <route url="login" roles="GUEST,USER"/>
        <route url="index" roles="USER"/>
        <route url="logout" roles="USER,ADMINISTRATOR"/>
        <route url="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>
');
        $this->xml_xml_dao = \simplexml_load_string('
<xml>
    <security dao_path="'.__DIR__.'">
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <form throttler="Authentication/'.__NAMESPACE__.'\\Authentication\\MockLoginThrottler"/>
        </authentication>
        <authorization>
            <by_dao page_dao="Authorization/'.__NAMESPACE__.'\\Authorization\\MockPageAuthorizationDAO" user_dao="Authorization/'.__NAMESPACE__.'\\Authorization\\MockUserAuthorizationDAO"/>
        </authorization>
    </security>
    <users roles="GUEST">
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'"/>
    </users>
</xml>
');
        $this->xml_xml_xml = \simplexml_load_string('
<xml>
    <security dao_path="'.__DIR__.'">
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <form throttler="Authentication/'.__NAMESPACE__.'\\Authentication\\MockLoginThrottler"/>
        </authentication>
        <authorization>
            <by_route/>
        </authorization>
    </security>
    <users roles="GUEST">
        <user id="1" username="test" password="'.password_hash("me", PASSWORD_BCRYPT).'" roles="USER"/>
    </users>
    <routes>
        <route url="login" roles="GUEST,USER"/>
        <route url="index" roles="USER"/>
        <route url="logout" roles="USER,ADMINISTRATOR"/>
        <route url="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>
');
        $this->xml_oauth2_dao = \simplexml_load_string('
<xml>
    <security dao_path="'.__DIR__.'">
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <oauth2 dao="Authentication/'.__NAMESPACE__.'\\Authentication\\MockVendorAuthenticationDAO"/>
        </authentication>
        <authorization>
            <by_dao page_dao="Authorization/'.__NAMESPACE__.'\\Authorization\\MockPageAuthorizationDAO" user_dao="Authorization/'.__NAMESPACE__.'\\Authorization\\MockUserAuthorizationDAO"/>
        </authorization>
    </security>
</xml>
');
        $this->xml_oauth2_xml = \simplexml_load_string('
<xml>
    <security dao_path="'.__DIR__.'">
        <csrf secret="'.$secret.'"/>
        <persistence>
            <synchronizer_token secret="'.$secret.'"/>
        </persistence>
        <authentication>
            <oauth2 dao="Authentication/'.__NAMESPACE__.'\\Authentication\\MockVendorAuthenticationDAO"/>
        </authentication>
        <authorization>
            <by_route/>
        </authorization>
    </security>
    <routes>
        <route url="login" roles="GUEST,USER"/>
        <route url="login/facebook" roles="GUEST"/>
        <route url="index" roles="USER"/>
        <route url="logout" roles="USER,ADMINISTRATOR"/>
        <route url="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>
');
    }

    public function getUserID()
    {
        $results = [];
        
        $xmls = ["dao_dao", "dao_xml", "xml_xml", "xml_dao"];
        foreach ($xmls as $name) {
            $results = array_merge($results, $this->testNormal($name));
        }
        
        $xmls = ["oauth2_dao", "oauth2_xml"];
        foreach ($xmls as $name) {
            $results = array_merge($results, $this->testOAuth2($name));
        }
                
        return $results;
    }
    
    private function testNormal(string $name): array
    {
        $results = [];
        
        $xml = $this->{"xml_".$name};
        try {
            new Wrapper($xml, $this->getRequest("asdf"));
            $results[] = new Result(false, "path not found: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="not_found", "not found: ".$name);
        }
        
        $wrapper = new Wrapper($xml, $this->getRequest("login"));
        $results[] = new Result($wrapper->getUserID()==null, "get login: ".$name);
        $csrfToken = $wrapper->getCsrfToken();
        
        try {
            new Wrapper($xml, $this->getRequest("login", "POST", ["username"=>"test", "password"=>"me1", "csrf"=>$csrfToken]));
            $results[] = new Result(false, "login failed: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="login_failed", "login failed: ".$name);
        }
        
        $accessToken = "";
        try {
            new Wrapper($xml, $this->getRequest("login", "POST", ["username"=>"test", "password"=>"me", "csrf"=>$csrfToken]));
            $results[] = new Result(false, "path not found: ".$name);
        } catch(SecurityPacket $packet) {
            $accessToken = $packet->getAccessToken();
            $results[] = new Result($packet->getStatus()=="login_ok", "login ok: ".$name);
        }
        
        $wrapper = new Wrapper($xml, $this->getRequest("index", "GET", [], $accessToken));
        $results[] = new Result($wrapper->getUserID()==1, "index: ".$name);
        
        try {
            new Wrapper($xml, $this->getRequest("administration", "GET", [], $accessToken));
            $results[] = new Result(false, "forbidden: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="forbidden", "forbidden: ".$name);
        }
        
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("logout", "GET", [], $accessToken));
            $results[] = new Result(false, "logout: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="logout_ok", "logout ok: ".$name);
        }
        
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("logout"));
            $results[] = new Result(false, "logout failed: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="logout_failed", "logout failed: ".$name);
        }
        
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("index"));
            $results[] = new Result(false, "unauthorized: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="unauthorized", "unauthorized: ".$name);
        }
        
        return $results;
    }
    
    private function testOAuth2(string $name): array
    {
        $results = [];
        
        $drivers = [new MockOauth2Driver("Facebook")];
        
        $xml = $this->{"xml_".$name};
        try {
            new Wrapper($xml, $this->getRequest("asdf"), $drivers);
            $results[] = new Result(false, "path not found: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="not_found", "not found: ".$name);
        }
        
        $wrapper = new Wrapper($xml, $this->getRequest("login"), $drivers);
        $results[] = new Result($wrapper->getUserID()==null, "get login: ".$name);
        $csrfToken = $wrapper->getCsrfToken();
        
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("login/facebook"), $drivers);
            $results[] = new Result(false, "authorization code: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="redirect" && $packet->getCallback()=="qwerty", "authorization code: ".$name);
        }
                
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("login/facebook", "GET", ["error"=>"asdfg"]), $drivers);
            $results[] = new Result(false, "bad authorization code: ".$name);
        } catch(OAuth2Exception $e) {
            $results[] = new Result(true, "bad authorization code: ".$name);
        }
        
        $accessToken = "";
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("login/facebook", "GET", ["code"=>"qwerty", "state"=>$csrfToken]), $drivers);
            $results[] = new Result(false, "access token: ".$name);
        } catch(SecurityPacket $packet) {
            $accessToken = $packet->getAccessToken();
            $results[] = new Result($packet->getStatus()=="login_ok", "access token: ".$name);
        }
        
        $wrapper = new Wrapper($xml, $this->getRequest("index", "GET", [], $accessToken), $drivers);
        $results[] = new Result($wrapper->getUserID()==1, "index: ".$name);
        
        try {
            new Wrapper($xml, $this->getRequest("administration", "GET", [], $accessToken), $drivers);
            $results[] = new Result(false, "forbidden: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="forbidden", "forbidden: ".$name);
        }
        
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("logout", "GET", [], $accessToken), $drivers);
            $results[] = new Result(false, "logout: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="logout_ok", "logout ok: ".$name);
        }
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("logout"), $drivers);
            $results[] = new Result(false, "logout failed: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="logout_failed", "logout failed: ".$name);
        }
        
        try {
            $wrapper = new Wrapper($xml, $this->getRequest("index"), $drivers);
            $results[] = new Result(false, "unauthorized: ".$name);
        } catch(SecurityPacket $packet) {
            $results[] = new Result($packet->getStatus()=="unauthorized", "unauthorized: ".$name);
        }
        
        return $results;
    }
        

    public function getCsrfToken()
    {
        $wrapper = new Wrapper($this->xml_dao_dao, $this->getRequest("login"));
        return new Result($wrapper->getCsrfToken()?true:false);
    }
        

    public function getAccessToken()
    {
        $results = [];
        
        $wrapper = new Wrapper($this->xml_dao_dao, $this->getRequest("login"));
        $results[] = new Result($wrapper->getAccessToken()==null, "not logged in");
        
        $accessToken = "";
        try {
            new Wrapper($this->xml_dao_dao, $this->getRequest("login", "POST", ["username"=>"test", "password"=>"me", "csrf"=>$wrapper->getCsrfToken()]));
        } catch(SecurityPacket $packet) {
            $accessToken = $packet->getAccessToken();
        }
        
        $wrapper = new Wrapper($this->xml_dao_dao, $this->getRequest("index", "GET", [], $accessToken));
        $results[] = new Result($wrapper->getAccessToken()==$accessToken, "logged in");
        
        return $results;
    }
        
    private function getRequest(string $uri, string $method="GET", array $parameters=[], string $accessToken=""): Request
    {
        $request = new Request();
        $request->setUri($uri);
        $request->setMethod($method);
        $request->setParameters($parameters);
        $request->setContextPath("");
        $request->setIpAddress("127.0.0.1");
        $request->setAccessToken($accessToken);
        return $request;
    }
}
