<?php

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

admin_session_start();
if (admin_logged_in()) {
    header('Location: dashboard.php', true, 302);
    exit;
}

$error = '';
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $pdo = seccheck_pdo();
    if (! $pdo instanceof PDO) {
        $error = 'Base de dados não configurada. Crie config/database.php (veja config/database.example.php) e importe o SQL.';
    } elseif ($username === '' || $password === '') {
        $error = 'Preencha utilizador e senha.';
    } else {
        $st = $pdo->prepare('SELECT id, username, password_hash FROM usuarios_admin WHERE username = ? LIMIT 1');
        $st->execute([$username]);
        $row = $st->fetch();
        if ($row && password_verify($password, $row['password_hash'])) {
            $_SESSION['admin_id'] = (int) $row['id'];
            $_SESSION['admin_username'] = (string) $row['username'];
            header('Location: dashboard.php', true, 302);
            exit;
        }
        $error = 'Utilizador ou senha inválidos.';
    }
}
?>
<!DOCTYPE html>
<html lang="pt-BR" data-bs-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SecCheck — Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body class="d-flex align-items-center min-vh-100">
<div class="container" style="max-width: 420px;">
    <div class="card sec-card border-0 shadow-lg">
        <div class="card-body p-4">
            <h1 class="h4 text-info mb-3">Painel administrativo</h1>
            <p class="small text-secondary mb-4">Aceda para ver auditorias, scores e percentagens por severidade.</p>
            <?php if ($error !== '') : ?>
                <div class="alert alert-danger small"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
            <?php endif; ?>
            <form method="post" action="login.php" autocomplete="off">
                <div class="mb-3">
                    <label class="form-label small text-secondary" for="username">Utilizador</label>
                    <input class="form-control" type="text" name="username" id="username" required maxlength="64">
                </div>
                <div class="mb-3">
                    <label class="form-label small text-secondary" for="password">Senha</label>
                    <input class="form-control" type="password" name="password" id="password" required>
                </div>
                <button type="submit" class="btn btn-info text-dark w-100 fw-semibold">Entrar</button>
            </form>
            <p class="small text-muted mt-3 mb-0">
                Primeira vez: importe <code>database/schemas/criar_tabelas.sql</code> e
                <code>database/seeds/admin_inicial.sql</code>. Utilizador predefinido: <strong>admin</strong> /
                senha: <strong>password</strong> (altere já).
            </p>
        </div>
    </div>
    <p class="text-center mt-3 small"><a href="../index.html" class="link-secondary">← Voltar ao verificador</a></p>
</div>
</body>
</html>
