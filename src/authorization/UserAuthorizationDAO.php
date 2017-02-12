<?php
interface UserAuthorizationDAO {
    function isAllowed(Page $page);
    function setUserID($userID);
}