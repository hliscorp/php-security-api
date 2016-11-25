<?php
require_once (dirname(dirname(__DIR__))."/src/token/Encryption.php");

$encryption = new Encryption('X5&*k%6{f*7}G721d9Kn!47/,l2uSE');
$data = "lucinda";
$encryptedData = "";

try {
    $encryptedData = $encryption->encrypt($data);
    echo "encrypt: OK\n";
} catch(EncryptionException $e) {
    echo "encrypt: NOK\n";
}

try {
    if($encryption->decrypt($encryptedData)!=$data) throw new EncryptionException();
    echo "decrypt: OK\n";
} catch(EncryptionException $e) {
    echo "decrypt: NOK\n";
}