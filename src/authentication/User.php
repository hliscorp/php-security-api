<?php
interface User {
    function isAllowed(Page $page);
    function login(LoginCredentials $credentials);
    function logout();
    function getId();
}