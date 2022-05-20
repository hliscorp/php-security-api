<?php

namespace Test\Lucinda\WebSecurity\Authentication\Form;

use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authentication\Form\LoginConfiguration;

class LoginConfigurationTest
{
    private LoginConfiguration $configuration1;
    private LoginConfiguration $configuration2;

    public function __construct()
    {
        $xml1 = simplexml_load_string('
<security>
    <authentication>
        <form>
            <login parameter_username="user" parameter_password="pass"   parameter_rememberMe="rm" page="test" target="me"/>  
        </form>
    </authentication>
</security>');
        $this->configuration1 = new LoginConfiguration($xml1->authentication->form);
        $xml2 = simplexml_load_string('
<security>
    <authentication>
        <form>
        </form>
    </authentication>
</security>');
        $this->configuration2 = new LoginConfiguration($xml2->authentication->form);
    }


    public function getUsername()
    {
        $output = [];
        $output[] = new Result($this->configuration1->getUsername() == "user", "manual");
        $output[] = new Result($this->configuration2->getUsername() == "username", "implied");
        return $output;
    }


    public function getPassword()
    {
        $output = [];
        $output[] = new Result($this->configuration1->getPassword() == "pass", "manual");
        $output[] = new Result($this->configuration2->getPassword() == "password", "implied");
        return $output;
    }


    public function getRememberMe()
    {
        $output = [];
        $output[] = new Result($this->configuration1->getRememberMe() == "rm", "manual");
        $output[] = new Result($this->configuration2->getRememberMe() == "remember_me", "implied");
        return $output;
    }


    public function getSourcePage()
    {
        $output = [];
        $output[] = new Result($this->configuration1->getSourcePage() == "test", "manual");
        $output[] = new Result($this->configuration2->getSourcePage() == "", "implied");
        return $output;
    }


    public function getDestinationPage()
    {
        $output = [];
        $output[] = new Result($this->configuration1->getDestinationPage() == "me", "manual");
        $output[] = new Result($this->configuration2->getDestinationPage() == "", "implied");
        return $output;
    }
}
