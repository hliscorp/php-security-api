<?php
interface PersistenceDriver {
	function load();
	function save();
}