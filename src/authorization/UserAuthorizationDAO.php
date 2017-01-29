<?php
interface UserAuthorizationDAO {
    function isAllowed(Page $page);
}