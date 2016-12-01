<?php
namespace OAuth2;

/**
 * Basic cURL implementation of OAuth2 request execution in accordance to RFC6749.
 */
class DefaultRequestExecutor implements RequestExecutor {
	protected $headers = array('Content-Type: application/x-www-form-urlencoded');
		
	/**
	 * Adds authorization token header.
	 * 
	 * @param string $accessToken
	 */
	public function addAuthorizationHeader($accessToken) {
		$this->headers[] = "Authorization: Bearer ".$accessToken;		
	}
	
	/**
	 * {@inheritDoc}
	 * @see \OAuth2\RequestExecutor::execute()
	 */
	public function execute($endpointURL, $parameters) {
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL,$endpointURL);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($parameters));
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www-form-urlencoded'));
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		try {
			$server_output = curl_exec ($ch);
			if($server_output===false) {
				throw new ClientException(curl_error($ch));
			}
			return $server_output;
		} finally {
			curl_close ($ch);
		}
	}
}