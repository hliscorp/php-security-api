<?php
interface UserAuthorizationDAO {
    function isAllowed(PageAuthorizationDAO $page);
    function setID($userID);
    function getID();
}