<?php
require __DIR__ . '/vendor/autoload.php';
try {
    new Lucinda\UnitTest\ConsoleController("unit-tests.xml", "local");
} catch (Exception $e) {
    echo $e->getMessage();
}

/**
    public function setAccessToken(): void
    {
        if (empty($_SERVER["HTTP_AUTHORIZATION"]) || stripos($_SERVER["HTTP_AUTHORIZATION"], "Bearer ")!==0) {
            return;
        }
        
        $this->accessToken = trim(substr($_SERVER["HTTP_AUTHORIZATION"], 7));
    }

*/