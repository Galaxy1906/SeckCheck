<?php

function admin_session_start(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_name('SECCHECKADMIN');
        session_start();
    }
}

function admin_logged_in(): bool
{
    admin_session_start();

    return isset($_SESSION['admin_id'], $_SESSION['admin_username'])
        && (int) $_SESSION['admin_id'] > 0
        && is_string($_SESSION['admin_username'])
        && $_SESSION['admin_username'] !== '';
}

function require_admin(): void
{
    if (! admin_logged_in()) {
        header('Location: login.php', true, 302);
        exit;
    }
}

function admin_logout(): void
{
    admin_session_start();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}
