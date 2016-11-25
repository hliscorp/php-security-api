<?php
require_once (dirname(__DIR__)."/src/User.php");
require_once (dirname(__DIR__)."/src/Page.php");
require_once (dirname(__DIR__)."/src/authentication/LoginCredentials.php");

class TestUser implements User {
    public function isAllowed(Page $page) {
        return true;
    }
    public function login(LoginCredentials $credentials) {
        return true;
    }
    function logout() {
        return true;
    }
    function getUniqueID() {
        return 123456;
    }
}