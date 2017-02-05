<?php
interface PersistenceDriver {
	function load();
	function save($userID);
	function clear($userID);
}