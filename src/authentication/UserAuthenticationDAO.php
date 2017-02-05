<?php
interface UserAuthenticationDAO {
    function login(LoginCredentials $credentials);
    function logout($userID);
}