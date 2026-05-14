<?php

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

require_admin();

$pdo = seccheck_pdo();
$dbOk = $pdo instanceof PDO;

$total = 0;
$avgScore = null;
$bySeverity = [];
$recent = [];
$dbError = '';

if (! $dbOk) {
    $dbError = 'Configure config/database.php e importe o esquema SQL.';
} else {
    try {
        $total = (int) $pdo->query('SELECT COUNT(*) FROM auditorias')->fetchColumn();
        $rowAvg = $pdo->query('SELECT ROUND(AVG(score_0_100), 1) AS a FROM auditorias')->fetch();
        $avgScore = $rowAvg['a'] !== null ? (float) $rowAvg['a'] : null;

        $st = $pdo->query('SELECT severity, COUNT(*) AS n FROM auditorias GROUP BY severity');
        while ($r = $st->fetch()) {
            $bySeverity[$r['severity']] = (int) $r['n'];
        }

        $st2 = $pdo->query(
            'SELECT analysis_id, created_at, score_0_100, severity, entropy_bits, password_length, charset_type, bruteforce_estimate '
            . 'FROM auditorias ORDER BY id DESC LIMIT 100'
        );
        $recent = $st2->fetchAll();
    } catch (Throwable $e) {
        $dbError = 'Erro ao ler auditorias. Confirme que executou o SQL atualizado (coluna score_0_100).';
    }
}

$labels = [
    'CRITICAL' => 'Crítica',
    'MEDIUM'   => 'Média',
    'STRONG'   => 'Forte',
];
$order = ['CRITICAL', 'MEDIUM', 'STRONG'];
?>
<!DOCTYPE html>
<html lang="pt-BR" data-bs-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SecCheck — Painel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body class="min-vh-100">
<nav class="navbar navbar-dark border-bottom border-secondary border-opacity-25">
    <div class="container-fluid">
        <span class="navbar-brand text-info"><strong>SecCheck</strong> — Admin</span>
        <span class="navbar-text small text-secondary me-3">
            Olá, <?= htmlspecialchars((string) ($_SESSION['admin_username'] ?? ''), ENT_QUOTES, 'UTF-8') ?>
        </span>
        <a class="btn btn-sm btn-outline-danger" href="logout.php">Sair</a>
    </div>
</nav>

<main class="container py-4">
    <?php if ($dbError !== '') : ?>
        <div class="alert alert-warning"><?= htmlspecialchars($dbError, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <?php if ($dbOk && $dbError === '') : ?>
        <div class="row g-3 mb-4">
            <div class="col-md-4">
                <div class="sec-stat p-3 rounded-3 h-100">
                    <div class="small text-secondary text-uppercase">Análises registadas</div>
                    <div class="display-6 text-info"><?= (int) $total ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="sec-stat p-3 rounded-3 h-100">
                    <div class="small text-secondary text-uppercase">Score médio (0–100)</div>
                    <div class="display-6 text-info"><?= $avgScore !== null ? htmlspecialchars((string) $avgScore, ENT_QUOTES, 'UTF-8') : '—' ?></div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="sec-stat p-3 rounded-3 h-100">
                    <div class="small text-secondary text-uppercase mb-2">Distribuição por severidade</div>
                    <?php foreach ($order as $sev) :
                        $n = $bySeverity[$sev] ?? 0;
                        $pct = $total > 0 ? round(100 * $n / $total, 1) : 0.0;
                        $cls = $sev === 'CRITICAL' ? 'bg-danger' : ($sev === 'MEDIUM' ? 'bg-warning' : 'bg-success');
                        ?>
                        <div class="mb-2">
                            <div class="d-flex justify-content-between small">
                                <span><?= htmlspecialchars($labels[$sev] ?? $sev, ENT_QUOTES, 'UTF-8') ?></span>
                                <span><?= htmlspecialchars((string) $pct, ENT_QUOTES, 'UTF-8') ?>% (<?= (int) $n ?>)</span>
                            </div>
                            <div class="progress" style="height:8px;">
                                <div class="progress-bar <?= $cls ?>" style="width: <?= min(100, $pct) ?>%;"></div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <h2 class="h5 text-secondary mb-3">Últimas auditorias</h2>
        <div class="table-responsive sec-stat rounded-3">
            <table class="table table-dark table-striped table-sm align-middle mb-0">
                <thead>
                <tr class="small text-secondary">
                    <th>Data</th>
                    <th>ID análise</th>
                    <th>Score %</th>
                    <th>Severidade</th>
                    <th>Entropia (bits)</th>
                    <th>Comp.</th>
                    <th>Charset</th>
                    <th>Tempo (GPU)</th>
                </tr>
                </thead>
                <tbody>
                <?php if ($recent === []) : ?>
                    <tr><td colspan="8" class="text-center text-secondary py-4">Ainda não há registos. Use o verificador público para gerar análises.</td></tr>
                <?php else : ?>
                    <?php foreach ($recent as $row) : ?>
                        <tr>
                            <td class="small text-nowrap"><?= htmlspecialchars((string) $row['created_at'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td class="small font-monospace"><?= htmlspecialchars((string) $row['analysis_id'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td><strong><?= (int) $row['score_0_100'] ?></strong></td>
                            <td><?= htmlspecialchars((string) $row['severity'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td><?= htmlspecialchars((string) $row['entropy_bits'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td><?= (int) $row['password_length'] ?></td>
                            <td class="small"><?= htmlspecialchars((string) $row['charset_type'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td class="small"><?= htmlspecialchars((string) $row['bruteforce_estimate'], ENT_QUOTES, 'UTF-8') ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>

    <p class="mt-4 small text-muted">
        <a href="../index.html" class="link-secondary">← Site público</a>
    </p>
</main>
</body>
</html>
