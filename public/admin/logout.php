<?php

require_once __DIR__ . '/includes/auth.php';

admin_logout();
header('Location: login.php', true, 302);
exit;
