<?php
interface PageAuthorizationDAO {
    function isPublic();
    function isFound();
    function setPage($path);
}