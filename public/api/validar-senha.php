<?php declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Método não permitido. Utilize POST.'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (version_compare(PHP_VERSION, '8.1.0', '<')) {
    http_response_code(500);
    echo json_encode([
        'error' => 'Este projeto precisa de PHP 8.1 ou superior (sintaxe readonly). Versão atual: ' . PHP_VERSION,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$core = __DIR__ . '/../../src/SecCheck.php';
if (! is_file($core)) {
    http_response_code(500);
    echo json_encode([
        'error' => 'Núcleo não encontrado: copie a pasta inteira do projeto para o htdocs. '
            . 'É obrigatório existir o arquivo src/SecCheck.php ao lado da pasta public (não copie só a pasta public).',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Lê "password" do corpo JSON e/ou do POST.
 * No XAMPP, em alguns casos o Content-Type do fetch não chega como "application/json";
 * por isso também tentamos json_decode no php://input quando o corpo parece JSON.
 */
$password = null;
$contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
$raw = file_get_contents('php://input');

if (stripos($contentType, 'application/json') !== false) {
    $data = is_string($raw) ? json_decode($raw, true) : null;
    if (is_array($data) && array_key_exists('password', $data)) {
        $password = $data['password'];
    }
} elseif (is_string($raw) && $raw !== '' && ($raw[0] === '{' || $raw[0] === '[')) {
    $data = json_decode($raw, true);
    if (is_array($data) && array_key_exists('password', $data)) {
        $password = $data['password'];
    }
}

if ($password === null && array_key_exists('password', $_POST)) {
    $password = $_POST['password'];
}

if ($password === null) {
    http_response_code(400);
    echo json_encode(['error' => 'O campo "password" é obrigatório e não pode ser nulo.'], JSON_UNESCAPED_UNICODE);
    exit;
}

if (! is_string($password)) {
    if (is_scalar($password)) {
        $password = (string) $password;
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'O campo "password" deve ser enviado como texto (string).'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

require_once $core;
require_once __DIR__ . '/../../config/pdo.php';

try {
    $analyzer = SecCheckFactory::create();
    $result = $analyzer->analyze($password);

    try {
        $pdo = seccheck_pdo();
        if ($pdo instanceof PDO) {
            $bf = '';
            if (isset($result['attack_simulation'][2]['time'])) {
                $bf = (string) $result['attack_simulation'][2]['time'];
            }
            if (strlen($bf) > 255) {
                $bf = substr($bf, 0, 252) . '...';
            }
            $ins = $pdo->prepare(
                'INSERT INTO auditorias (analysis_id, entropy_bits, score_0_100, severity, password_length, charset_type, bruteforce_estimate) '
                . 'VALUES (:analysis_id, :entropy_bits, :score_0_100, :severity, :password_length, :charset_type, :bruteforce_estimate)'
            );
            $ins->execute([
                ':analysis_id'          => (string) $result['meta']['analysis_id'],
                ':entropy_bits'         => (float) $result['entropy']['effective_bits'],
                ':score_0_100'          => (int) $result['strength']['score'],
                ':severity'             => (string) $result['strength']['severity_level'],
                ':password_length'      => (int) $result['input']['length'],
                ':charset_type'         => (string) $result['input']['charset_type'],
                ':bruteforce_estimate' => $bf,
            ]);
        }
    } catch (Throwable) {
        // falha de BD não impede a resposta JSON da análise
    }

    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Não foi possível concluir a análise.'], JSON_UNESCAPED_UNICODE);
}
