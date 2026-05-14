<?php

/**
 * SecCheck - Analisador de Força de Senhas (Enterprise-Grade)
 *
 * Referências:
 *  [1] NIST SP 800-63B  – Digital Identity Guidelines
 *  [2] OWASP Password Storage Cheat Sheet
 *  [3] zxcvbn – Realistic Password Strength Estimation (Dropbox)
 *  [4] OWASP Authentication Cheat Sheet
 *
 * @version 2.0.0
 */

// ─────────────────────────────────────────────────────────────────────────────
// Value Objects
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Representa o charset detectado em uma senha.
 * Imutável – calculado uma única vez e reutilizado.
 */
final class DetectedCharset
{
    public function __construct(
        public readonly bool $hasNumbers,
        public readonly bool $hasLowercase,
        public readonly bool $hasUppercase,
        public readonly bool $hasAsciiSymbols,
        public readonly bool $hasUnicode,
    ) {}

    /**
     * Tamanho REAL do espaço de símbolos:
     * soma apenas os grupos que a senha efetivamente usa.
     *
     * CORREÇÃO CRÍTICA do código original:
     *   - Original retornava CHARSET_SYMBOLS (95) para qualquer senha com símbolo,
     *     independente de conter letras/números → superestimava entropia.
     *   - Novo código soma somente os grupos presentes.
     */
    public function poolSize(): int
    {
        $size = 0;
        if ($this->hasNumbers)      $size += 10;   // 0-9
        if ($this->hasLowercase)    $size += 26;   // a-z
        if ($this->hasUppercase)    $size += 26;   // A-Z
        if ($this->hasAsciiSymbols) $size += 33;   // !-/ :-@ [-` {-~ (33 símbolos ASCII imprimíveis)
        if ($this->hasUnicode)      $size += 1024; // heurística conservadora p/ Unicode além do ASCII
        return max($size, 1);
    }

    public function label(): string
    {
        $groups = [];
        if ($this->hasLowercase || $this->hasUppercase) {
            $groups[] = match(true) {
                $this->hasLowercase && $this->hasUppercase => 'letras (A-Z, a-z)',
                $this->hasUppercase => 'maiúsculas (A-Z)',
                default              => 'minúsculas (a-z)',
            };
        }
        if ($this->hasNumbers)      $groups[] = 'números (0-9)';
        if ($this->hasAsciiSymbols) $groups[] = 'símbolos ASCII';
        if ($this->hasUnicode)      $groups[] = 'caracteres Unicode';
        return $groups ? implode(', ', $groups) : 'desconhecido';
    }
}

/**
 * Representa uma penalidade aplicada à entropia bruta.
 */
final class Penalty
{
    public function __construct(
        public readonly string $reason,
        public readonly float  $factor,   // multiplicador 0.0–1.0
    ) {}
}

/**
 * Cenário de ataque (velocidade configurável).
 */
final class AttackScenario
{
    public function __construct(
        public readonly string $name,
        public readonly float  $attemptsPerSecond,
        public readonly string $description,
    ) {}

    public static function online(): self
    {
        return new self(
            name: 'online',
            attemptsPerSecond: 100,
            description: 'Ataque online com rate-limit (100 tentativas/s)',
        );
    }

    public static function offlineSlow(): self
    {
        return new self(
            name: 'offline_slow',
            attemptsPerSecond: 1_000_000,
            description: 'Ataque offline lento – bcrypt/Argon2 (1 M/s)',
        );
    }

    public static function offlineFast(): self
    {
        return new self(
            name: 'offline_fast',
            attemptsPerSecond: 100_000_000_000,
            description: 'Ataque offline rápido – GPU cluster / hash fraco (100 B/s)',
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. EntropyCalculator  (SRP: cálculo matemático puro)
// ─────────────────────────────────────────────────────────────────────────────

final class EntropyCalculator
{
    /**
     * Entropia bruta: H = L × log₂(R)
     *
     * @param int $length     Comprimento da senha (em code points, não bytes)
     * @param int $poolSize   Tamanho do charset detectado
     */
    public function rawEntropy(int $length, int $poolSize): float
    {
        if ($length === 0 || $poolSize <= 1) {
            return 0.0;
        }
        return $length * log($poolSize, 2);
    }

    /**
     * Aplica penalidades e retorna entropia efetiva.
     *
     * @param float     $raw       Entropia bruta
     * @param Penalty[] $penalties Lista de penalidades detectadas
     */
    public function effectiveEntropy(float $raw, array $penalties): float
    {
        $effective = $raw;
        foreach ($penalties as $penalty) {
            $effective *= $penalty->factor;
        }
        return max($effective, 0.0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. BruteforceEstimator  (SRP: cálculo de tempo de ataque)
// ─────────────────────────────────────────────────────────────────────────────

final class BruteforceEstimator
{
    /**
     * Estima tempo de quebra para um dado espaço de busca e cenário de ataque.
     *
     * Usa entropia efetiva (não bruta) para evitar otimismo falso.
     *
     * @return array{scenario:string, description:string, time:string, raw_seconds:float}
     */
    public function estimate(float $effectiveEntropy, AttackScenario $scenario): array
    {
        // Keyspace = 2^H  (usa entropia efetiva, penalidades já aplicadas)
        // Para valores muito grandes, trabalhamos em log-space para evitar INF
        $logKeyspace = $effectiveEntropy; // log₂(keyspace) = H
        $logAttackSpeed = log($scenario->attemptsPerSecond, 2);
        $logSeconds = $logKeyspace - $logAttackSpeed;

        // Converte de volta para segundos apenas quando manejável
        $seconds = $logSeconds > 200
            ? PHP_INT_MAX          // "tempo astronômico"
            : pow(2, $logSeconds);

        return [
            'scenario'    => $scenario->name,
            'description' => $scenario->description,
            'time'        => $this->formatSeconds($seconds),
            'raw_seconds' => $seconds === PHP_INT_MAX ? PHP_INT_MAX : round($seconds, 2),
        ];
    }

    private function formatSeconds(float|int $seconds): string
    {
        if ($seconds === PHP_INT_MAX)   return '> trilhões de anos';
        if ($seconds < 0.001)           return '< 1 ms';
        if ($seconds < 1)               return round($seconds * 1000) . ' ms';

        $minutes = $seconds / 60;
        if ($minutes < 1)   return round($seconds, 1) . ' segundos';

        $hours = $minutes / 60;
        if ($hours < 1)     return round($minutes, 1) . ' minutos';

        $days = $hours / 24;
        if ($days < 1)      return round($hours, 1) . ' horas';

        $years = $days / 365.25;
        if ($years < 1)     return round($days, 1) . ' dias';
        if ($years < 1_000) return round($years, 1) . ' anos';

        $millennia = $years / 1_000;
        if ($millennia < 1_000) return round($millennia, 1) . ' milênios';

        return '> ' . number_format($years, 0, ',', '.') . ' anos';
    }
}
// ─────────────────────────────────────────────────────────────────────────────
// 3. PasswordStrengthAnalyzer  (SRP: análise qualitativa / heurísticas)
// ─────────────────────────────────────────────────────────────────────────────

final class PasswordStrengthAnalyzer
{
    /** Top-200 senhas mais usadas (HIBP / SecLists) — amostra representativa */
    private const COMMON_PASSWORDS = [
        'password','123456','12345678','qwerty','abc123','monkey','1234567',
        'letmein','trustno1','dragon','master','sunshine','princess','welcome',
        'shadow','superman','michael','football','baseball','iloveyou','admin',
        'login','hello','password1','senha','mudar123','q1w2e3r4','654321',
        '111111','000000','123321','987654321','pass','pass123',
    ];

    /** Sequências de teclado conhecidas */
    private const KEYBOARD_SEQUENCES = [
        'qwerty','qwertyuiop','asdfghjkl','zxcvbnm',
        '1qaz2wsx','!qaz@wsx','qazwsx','1234567890',
    ];

    /**
     * Detecta charset com suporte a Unicode (mb_* functions).
     *
     * CORREÇÃO: usa mb_strlen / mb_substr para não confundir bytes com caracteres.
     */
    public function detectCharset(string $password): DetectedCharset
    {
        $length = mb_strlen($password, 'UTF-8');
        $hasNumbers = $hasLower = $hasUpper = $hasSymbol = $hasUnicode = false;

        for ($i = 0; $i < $length; $i++) {
            $char = mb_substr($password, $i, 1, 'UTF-8');
            $cp   = mb_ord($char, 'UTF-8');   // code point Unicode

            if ($cp > 127) {
                $hasUnicode = true;
                continue;
            }

            // ASCII range
            if ($cp >= 48 && $cp <= 57)   { $hasNumbers = true; continue; }
            if ($cp >= 97 && $cp <= 122)  { $hasLower   = true; continue; }
            if ($cp >= 65 && $cp <= 90)   { $hasUpper   = true; continue; }
            if ($cp >= 33 && $cp <= 126)  { $hasSymbol  = true; }
            // cp < 33 (controle/espaço) são ignorados deliberadamente
        }

        return new DetectedCharset($hasNumbers, $hasLower, $hasUpper, $hasSymbol, $hasUnicode);
    }

    /**
     * Calcula todas as penalidades qualitativas.
     *
     * Inspirado nas heurísticas do zxcvbn [3].
     *
     * @return Penalty[]
     */
    public function detectPenalties(string $password): array
    {
        $penalties = [];
        $lower     = mb_strtolower($password, 'UTF-8');

        // ── Senha na lista de comuns ──────────────────────────────────────────
        if (in_array($lower, self::COMMON_PASSWORDS, true)) {
            $penalties[] = new Penalty('Senha extremamente comum (lista top-200)', 0.05);
            return $penalties; // inutilidade de checar mais se já é trivialmente fraca
        }

        // ── Senha muito curta ────────────────────────────────────────────────
        $length = mb_strlen($password, 'UTF-8');
        if ($length < 8) {
            $penalties[] = new Penalty('Comprimento abaixo do mínimo recomendado (8 chars)', 0.5);
        }

        // ── Caracteres repetidos (ex: "aaaaaaa", "1111") ────────────────────
        if ($this->hasExcessiveRepetition($password)) {
            $penalties[] = new Penalty('Alta repetição de caracteres', 0.4);
        }

        // ── Sequências numéricas (ex: "123456", "987654") ───────────────────
        if ($this->hasNumericSequence($lower)) {
            $penalties[] = new Penalty('Sequência numérica detectada', 0.5);
        }

        // ── Sequências alfabéticas (ex: "abcde") ────────────────────────────
        if ($this->hasAlphaSequence($lower)) {
            $penalties[] = new Penalty('Sequência alfabética detectada', 0.5);
        }

        // ── Padrão de teclado (ex: "qwerty", "1qaz") ────────────────────────
        foreach (self::KEYBOARD_SEQUENCES as $seq) {
            if (str_contains($lower, $seq)) {
                $penalties[] = new Penalty("Padrão de teclado detectado: \"$seq\"", 0.6);
                break;
            }
        }

        return $penalties;
    }

    /**
     * Converte entropia efetiva em score 0–100.
     *
     * Escala:
     *   0–28 bits  → 0–25
     *   28–36 bits → 25–50
     *   36–60 bits → 50–75
     *   60–80 bits → 75–90
     *   80+ bits   → 90–100
     */
    public function entropyToScore(float $entropy): int
    {
        return match(true) {
            $entropy <= 0  => 0,
            $entropy < 28  => (int) round(($entropy / 28) * 25),
            $entropy < 36  => (int) round(25 + (($entropy - 28) / 8) * 25),
            $entropy < 60  => (int) round(50 + (($entropy - 36) / 24) * 25),
            $entropy < 80  => (int) round(75 + (($entropy - 60) / 20) * 15),
            default        => (int) min(100, round(90 + (($entropy - 80) / 40) * 10)),
        };
    }

    /**
     * Gera recomendações baseadas na análise real (não genéricas).
     *
     * @param Penalty[] $penalties
     */
    public function buildRecommendations(
        float           $entropy,
        DetectedCharset $charset,
        array           $penalties,
        int             $length,
    ): array {
        $recs = [];

        foreach ($penalties as $p) {
            $recs[] = "⚠ {$p->reason}";
        }

        if ($length < 12) {
            $recs[] = 'Aumente para pelo menos 12 caracteres (16+ é ideal)';
        }

        if (!$charset->hasUppercase && !$charset->hasLowercase) {
            $recs[] = 'Adicione letras maiúsculas e minúsculas';
        } elseif (!$charset->hasUppercase || !$charset->hasLowercase) {
            $recs[] = 'Misture letras maiúsculas e minúsculas';
        }

        if (!$charset->hasNumbers) {
            $recs[] = 'Inclua dígitos numéricos (0-9)';
        }

        if (!$charset->hasAsciiSymbols) {
            $recs[] = 'Inclua símbolos especiais (!@#$%...)';
        }

        if ($entropy >= 80 && empty($penalties)) {
            $recs[] = '✓ Senha com boa entropia – mantenha-a única por serviço';
        }

        return array_values(array_unique($recs));
    }

    // ── Helpers privados ──────────────────────────────────────────────────────

    private function hasExcessiveRepetition(string $password): bool
    {
        $length = mb_strlen($password, 'UTF-8');
        if ($length < 4) return false;

        // Conta máximo de ocorrências de um único caractere
        $freq = [];
        for ($i = 0; $i < $length; $i++) {
            $c = mb_substr($password, $i, 1, 'UTF-8');
            $freq[$c] = ($freq[$c] ?? 0) + 1;
        }
        $maxFreq = max($freq);
        // Penaliza se > 50% dos chars são iguais
        return ($maxFreq / $length) > 0.5;
    }

    private function hasNumericSequence(string $lower): bool
    {
        // Detecta sequências numéricas de 4+ dígitos (crescente ou decrescente)
        preg_match_all('/\d+/', $lower, $matches);
        foreach ($matches[0] as $run) {
            if (mb_strlen($run) < 4) continue;
            $digits = array_map('intval', str_split($run));
            $diffs  = [];
            for ($i = 1; $i < count($digits); $i++) {
                $diffs[] = $digits[$i] - $digits[$i - 1];
            }
            // Todos os diffs iguais (±1 = sequência aritmética simples)
            if (count(array_unique($diffs)) === 1 && abs($diffs[0]) === 1) {
                return true;
            }
        }
        return false;
    }

    private function hasAlphaSequence(string $lower): bool
    {
        // Detecta 4+ letras consecutivas em ordem alfabética
        $letters = preg_replace('/[^a-z]/', '', $lower);
        $len     = strlen($letters);
        if ($len < 4) return false;

        $streak = 1;
        for ($i = 1; $i < $len; $i++) {
            if (ord($letters[$i]) - ord($letters[$i - 1]) === 1) {
                $streak++;
                if ($streak >= 4) return true;
            } else {
                $streak = 1;
            }
        }
        return false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. SeverityClassifier  (SRP: classificação de criticidade)
// ─────────────────────────────────────────────────────────────────────────────

final class SeverityClassifier
{
    // Thresholds baseados em entropia EFETIVA (não bruta)
    private const CRITICAL_MAX = 35;   // H_eff < 35 → CRÍTICO
    private const MEDIUM_MAX   = 60;   // 35 ≤ H_eff < 60 → MÉDIO
    // H_eff ≥ 60 → SEGURA

    /** @return array{level:string, color:string, label:string} */
    public function classify(float $effectiveEntropy): array
    {
        return match(true) {
            $effectiveEntropy < self::CRITICAL_MAX => [
                'level' => 'CRITICAL',
                'color' => '#dc3545',
                'label' => 'Crítica',
            ],
            $effectiveEntropy < self::MEDIUM_MAX => [
                'level' => 'MEDIUM',
                'color' => '#ffc107',
                'label' => 'Média',
            ],
            default => [
                'level' => 'STRONG',
                'color' => '#28a745',
                'label' => 'Forte',
            ],
        };
    }
}
// ─────────────────────────────────────────────────────────────────────────────
// 5. SecCheckAnalyzer  (Facade – orquestra os demais componentes)
// ─────────────────────────────────────────────────────────────────────────────

final class SecCheckAnalyzer
{
    public function __construct(
        private readonly EntropyCalculator       $entropyCalc,
        private readonly PasswordStrengthAnalyzer $strengthAnalyzer,
        private readonly BruteforceEstimator      $bruteforceEst,
        private readonly SeverityClassifier       $severityClassifier,
    ) {}

    /**
     * Ponto de entrada principal.
     *
     * EDGE CASES tratados:
     *  - Senha vazia → retorna resultado com entropia 0 e score 0
     *  - Senha exclusivamente Unicode → pool heurístico aplicado
     *  - Charset inválido / poolSize = 1 → entropia 0 (não gera exceção)
     */
    public function analyze(string $password): array
    {
        // ── Edge case: senha vazia ────────────────────────────────────────────
        if ($password === '') {
            return $this->emptyPasswordResult();
        }

        $length  = mb_strlen($password, 'UTF-8');
        $charset = $this->strengthAnalyzer->detectCharset($password);
        $pool    = $charset->poolSize();

        // ── Entropia bruta ────────────────────────────────────────────────────
        $rawEntropy = $this->entropyCalc->rawEntropy($length, $pool);

        // ── Penalidades ───────────────────────────────────────────────────────
        $penalties       = $this->strengthAnalyzer->detectPenalties($password);
        $effectiveEntropy = $this->entropyCalc->effectiveEntropy($rawEntropy, $penalties);

        // ── Classificação ─────────────────────────────────────────────────────
        $severity = $this->severityClassifier->classify($effectiveEntropy);
        $score    = $this->strengthAnalyzer->entropyToScore($effectiveEntropy);

        // ── Estimativas de tempo (3 cenários) ────────────────────────────────
        $bruteforce = [
            $this->bruteforceEst->estimate($effectiveEntropy, AttackScenario::online()),
            $this->bruteforceEst->estimate($effectiveEntropy, AttackScenario::offlineSlow()),
            $this->bruteforceEst->estimate($effectiveEntropy, AttackScenario::offlineFast()),
        ];

        // ── Recomendações ─────────────────────────────────────────────────────
        $recommendations = $this->strengthAnalyzer->buildRecommendations(
            $effectiveEntropy, $charset, $penalties, $length,
        );

        return [
            'meta' => [
                'analysis_id' => $this->generateAnalysisId(),
                'timestamp'   => (new DateTimeImmutable())->format(DateTimeInterface::ATOM),
                'version'     => '2.0.0',
            ],
            'input' => [
                'length'       => $length,
                'charset_pool' => $pool,
                'charset_type' => $charset->label(),
                'charset_groups' => [
                    'numbers'       => $charset->hasNumbers,
                    'lowercase'     => $charset->hasLowercase,
                    'uppercase'     => $charset->hasUppercase,
                    'ascii_symbols' => $charset->hasAsciiSymbols,
                    'unicode'       => $charset->hasUnicode,
                ],
            ],
            'entropy' => [
                'raw_bits'       => round($rawEntropy, 2),
                'effective_bits' => round($effectiveEntropy, 2),
                'penalties'      => array_map(
                    fn(Penalty $p) => ['reason' => $p->reason, 'factor' => $p->factor],
                    $penalties,
                ),
            ],
            'strength' => [
                'score'           => $score,          // 0–100
                'severity_level'  => $severity['level'],
                'severity_label'  => $severity['label'],
                'severity_color'  => $severity['color'],
            ],
            'attack_simulation' => $bruteforce,
            'recommendations'   => $recommendations,
            'security_note'     => 'Para armazenamento, use password_hash() com PASSWORD_ARGON2ID. '
                                 . 'Esta análise não substitui auditoria profissional.',
        ];
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function emptyPasswordResult(): array
    {
        return [
            'meta' => [
                'analysis_id' => $this->generateAnalysisId(),
                'timestamp'   => (new DateTimeImmutable())->format(DateTimeInterface::ATOM),
                'version'     => '2.0.0',
            ],
            'input'             => ['length' => 0, 'charset_pool' => 0, 'charset_type' => 'nenhum', 'charset_groups' => []],
            'entropy'           => ['raw_bits' => 0.0, 'effective_bits' => 0.0, 'penalties' => []],
            'strength'          => ['score' => 0, 'severity_level' => 'CRITICAL', 'severity_label' => 'Crítica', 'severity_color' => '#dc3545'],
            'attack_simulation' => [],
            'recommendations'   => ['Informe uma senha para análise'],
            'security_note'     => '',
        ];
    }

    private function generateAnalysisId(): string
    {
        return 'SCK2_' . (new DateTimeImmutable())->format('YmdHis') . '_' . bin2hex(random_bytes(4));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Factory helper  (simplifica instanciação)
// ─────────────────────────────────────────────────────────────────────────────

final class SecCheckFactory
{
    public static function create(): SecCheckAnalyzer
    {
        return new SecCheckAnalyzer(
            new EntropyCalculator(),
            new PasswordStrengthAnalyzer(),
            new BruteforceEstimator(),
            new SeverityClassifier(),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo / smoke-test  (só executa quando chamado diretamente)
// ─────────────────────────────────────────────────────────────────────────────

if (isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    $analyzer = SecCheckFactory::create();

    $tests = [
        '',                     // edge case: vazio
        '123',                  // crítica – curta, numérica
        'password',             // crítica – comum
        'abc123',               // crítica – comum
        'Abc@123!',             // média
        'Tr0ub4dor&3',          // forte (XKCD-style)
        'correct-horse-battery-staple', // passphrase longa
        str_repeat('A', 20),    // longa mas charset mínimo
        'こんにちは世界',            // Unicode
        'qwerty12345!',         // padrão de teclado + sequência
    ];

    foreach ($tests as $pwd) {
        $result = $analyzer->analyze($pwd);
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";
    }
}
