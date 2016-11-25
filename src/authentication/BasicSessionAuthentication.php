<?php
final class BasicSessionAuthentication implements Authentication {
    private $parameterName = "user_id";
    
    public function setUserIdHolderParam($parameterName="user_id") {
        $this->parameterName = $parameterName;
    }
    
    public function login(User $user, LoginCredentials $credentials) {
        $user->login($credentials);
        $_SESSION[$this->parameterName] = $user->getId();
    }
    
    public function logout(User $user) {
        $user->logout();
        unset($_SESSION[$this->parameterName]);
    }
}