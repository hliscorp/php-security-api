<?php
require_once (dirname(dirname(__DIR__))."/src/token/SynchronizerToken.php");

// generate password
$password = "lucinda";
$ip = "81.180.116.37";
$userID = 123456;
$token = "";

// check normal decryption/encryption
try {
    $st = new SynchronizerToken();
    $token = $st->encode($userID, $ip, $password, 3);
    $decryptedPayload = $st->decode($token, $ip, $password);
    if($decryptedPayload!=$userID) throw TokenException();
    echo "1: OK\n";
} catch(TokenException $e) {
    echo "1: NOK\n";
}

// check different ip
try {
    $st = new SynchronizerToken();
    $st->decode($token, "81.180.116.34", $password);
    echo "2: NOK\n";
} catch(TokenException $e) {
    echo "2: OK\n";
}

// check regeneration time
sleep(2);
try {
    $st = new SynchronizerToken();
    $st->decode($token, $ip, $password, 1);
    echo "3: NOK\n";
} catch(TokenRegenerationException $e) {
    echo "3: OK\n";
}

// check expiration time
sleep(2);
try {
    $st = new SynchronizerToken();
    $st->decode($token, $ip, $password);
    echo "4: NOK\n";
} catch(TokenException $e) {
    echo "4: OK\n";
}
