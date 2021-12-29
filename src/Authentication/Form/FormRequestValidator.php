<?php
namespace Lucinda\WebSecurity\Authentication\Form;

use Lucinda\WebSecurity\Request;

/**
 * Validates authentication requests in configuration.xml and encapsulates them into objects
 */
class FormRequestValidator
{
    const DEFAULT_PARAMETER_USERNAME = "username";
    const DEFAULT_PARAMETER_PASSWORD = "password";
    const DEFAULT_PARAMETER_REMEMBER_ME = "remember_me";
    const DEFAULT_TARGET_PAGE = "index";
    const DEFAULT_LOGIN_PAGE = "login";
    const DEFAULT_LOGOUT_PAGE = "logout";
    
    private \SimpleXMLElement $xml;
    private Request $request;
    
    /**
     * Matches POST request to XML tag &lt;form&gt;
     *
     * @param \SimpleXMLElement $xml
     * @param Request $request
     */
    public function __construct(\SimpleXMLElement $xml, Request $request)
    {
        $this->xml = $xml->authentication->form;
        $this->request = $request;
    }
    
    /**
     * Performs a form login
     *
     * @throws Exception
     * @return LoginRequest|NULL
     */
    public function login(): ?LoginRequest
    {
        $loginRequest = new LoginRequest();
        
        // set source page;
        $sourcePage = (string) $this->xml->login["page"];
        if (!$sourcePage) {
            $sourcePage = self::DEFAULT_LOGIN_PAGE;
        }
        if ($sourcePage != $this->request->getUri() || $this->request->getMethod()!="POST") {
            return null;
        }
        $loginRequest->setSourcePage($sourcePage);
        
        // get target page
        $targetPage = (string) $this->xml->login["target"];
        if (!$targetPage) {
            $targetPage = self::DEFAULT_TARGET_PAGE;
        }
        $loginRequest->setDestinationPage($targetPage);
        
        // get parameter names
        $parameterUsername = (string) $this->xml->login["parameter_username"];
        if (!$parameterUsername) {
            $parameterUsername = self::DEFAULT_PARAMETER_USERNAME;
        }
        $parameterPassword = (string) $this->xml->login["parameter_password"];
        if (!$parameterPassword) {
            $parameterPassword = self::DEFAULT_PARAMETER_PASSWORD;
        }
        $parameterRememberMe = (string) $this->xml->login["parameter_rememberMe"];
        if (!$parameterRememberMe) {
            $parameterRememberMe = self::DEFAULT_PARAMETER_REMEMBER_ME;
        }
        
        // set parameter values
        $requestParameters = $this->request->getParameters();
        if (empty($requestParameters[$parameterUsername])) {
            throw new Exception("POST parameter missing: ".$parameterUsername);
        }
        $loginRequest->setUsername($requestParameters[$parameterUsername]);
        if (empty($requestParameters[$parameterPassword])) {
            throw new Exception("POST parameter missing: ".$parameterPassword);
        }
        $loginRequest->setPassword($requestParameters[$parameterPassword]);
        $loginRequest->setRememberMe(!empty($requestParameters[$parameterRememberMe]));
        
        return $loginRequest;
    }
    
    /**
     * Performs a form logout
     *
     * @return LogoutRequest|NULL
     */
    public function logout(): ?LogoutRequest
    {
        $logoutRequest = new LogoutRequest();
        
        // set source page
        $sourcePage = (string) $this->xml->logout["page"];
        if (!$sourcePage) {
            $sourcePage = self::DEFAULT_LOGOUT_PAGE;
        }
        if ($sourcePage != $this->request->getUri()) {
            return null;
        }
        $logoutRequest->setSourcePage($this->request->getUri());
        
        // set destination page
        $targetPage = (string) $this->xml->logout["target"];
        if (!$targetPage) {
            $targetPage = self::DEFAULT_LOGIN_PAGE;
        }
        $logoutRequest->setDestinationPage($targetPage);
        
        return $logoutRequest;
    }
}
