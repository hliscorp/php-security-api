<?php
interface PageAuthorizationDAO {
    function isPublic();
    function setID($path);
    function getID();
}