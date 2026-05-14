<?php

require_once __DIR__ . '/includes/auth.php';

admin_session_start();
if (admin_logged_in()) {
    header('Location: dashboard.php', true, 302);
} else {
    header('Location: login.php', true, 302);
}
exit;
