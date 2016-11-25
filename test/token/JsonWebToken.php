<?php
require_once (dirname(dirname(__DIR__))."/src/token/JsonWebToken.php");

// generate payload
$payload = new JsonWebTokenPayload();
$payload->setAudience("www.example.com");
$payload->setApplicationId("ap_id");
$payload->setIssuer("sts");
$payload->setIssuedTime(time());
$payload->setStartTime(time()+1);
$payload->setEndTime(time()+3);
$payload->setSubject("123456");

// define password
$password = "lucinda";
$token = "";

// check start time
try {
    $jwt = new JsonWebToken();
    $token = $jwt->encode($payload, $password);
    $jwt->decode($token, $password, new JsonWebTokenPayload());
    echo "1: NOK\n";
} catch(TokenException $e) {
    echo "1: OK\n";
}

// check normal decryption/encryption
sleep(1);
try {
    $jwt = new JsonWebToken();
    $jwt->decode($token, $password, new JsonWebTokenPayload());
    echo "2: OK\n";
} catch(TokenException $e) {
    echo "2: NOK\n";
}

// check validation failure
try {
    $matchToken = new JsonWebTokenPayload();
    $matchToken->setAudience("www.google.com");
    $jwt = new JsonWebToken();
    $jwt->decode($token, $password, $matchToken);
    echo "3: NOK\n";
} catch(TokenException $e) {
    echo "3: OK\n";
}

// check regeneration time
sleep(1);
try {
    $jwt = new JsonWebToken();
    $jwt->decode($token, $password, new JsonWebTokenPayload(), 1);
    echo "4: NOK\n";
} catch(TokenRegenerationException $e) {
    echo "4: OK\n";
}

// check expiration time
sleep(2);
try {
    $jwt = new JsonWebToken();
    $jwt->decode($token, $password, new JsonWebTokenPayload());
    echo "5: NOK\n";
} catch(TokenException $e) {
    echo "5: OK\n";
}
