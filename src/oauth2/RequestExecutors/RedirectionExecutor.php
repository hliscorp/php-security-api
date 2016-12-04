<?php
namespace OAuth2;

class RedirectionExecutor implements RequestExecutor {
	public function execute($url, $parameters) {
		header("Location: ".$url."?".http_build_query($parameters));
		exit();
	}
}