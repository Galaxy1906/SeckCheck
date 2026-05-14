<?php

/**
 * Ligação PDO partilhada (API + admin). Devolve null se config/database.php não existir ou falhar a ligação.
 */
function seccheck_pdo(): ?PDO
{
    static $cache = null;
    if ($cache instanceof PDO) {
        return $cache;
    }

    $file = __DIR__ . DIRECTORY_SEPARATOR . 'database.php';
    if (! is_file($file)) {
        return null;
    }

    /** @var array{dsn:string,user:string,pass:string} $cfg */
    $cfg = require $file;
    try {
        $cache = new PDO($cfg['dsn'], $cfg['user'], $cfg['pass'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    } catch (Throwable) {
        return null;
    }

    return $cache;
}
