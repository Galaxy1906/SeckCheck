<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestDox;

require_once __DIR__ . '/src/SecCheck.php';

// ═════════════════════════════════════════════════════════════════════════════
// EntropyCalculatorTest
// ═════════════════════════════════════════════════════════════════════════════

final class EntropyCalculatorTest extends TestCase
{
    private EntropyCalculator $calc;

    protected function setUp(): void
    {
        $this->calc = new EntropyCalculator();
    }

    // ── rawEntropy ────────────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Senha vazia retorna entropia 0')]
    public function rawEntropy_emptyPassword_returnsZero(): void
    {
        self::assertSame(0.0, $this->calc->rawEntropy(0, 26));
    }

    #[Test]
    #[TestDox('Charset unitário retorna entropia 0 (sem variabilidade)')]
    public function rawEntropy_singleCharset_returnsZero(): void
    {
        self::assertSame(0.0, $this->calc->rawEntropy(10, 1));
    }

    #[Test]
    #[TestDox('Charset zero (inválido) retorna entropia 0')]
    public function rawEntropy_zeroCharset_returnsZero(): void
    {
        self::assertSame(0.0, $this->calc->rawEntropy(5, 0));
    }

    #[Test]
    #[TestDox('H = L × log₂(R): 8 chars × log₂(26) ≈ 37.6 bits')]
    public function rawEntropy_8charsLowercase_approximatelyCorrect(): void
    {
        $entropy = $this->calc->rawEntropy(8, 26);
        self::assertEqualsWithDelta(8 * log(26, 2), $entropy, 0.001);
    }

    #[Test]
    #[TestDox('H = L × log₂(R): 12 chars × log₂(95) ≈ 78.8 bits')]
    public function rawEntropy_12charsFullAscii_approximatelyCorrect(): void
    {
        // pool correto: 10+26+26+33 = 95
        $entropy = $this->calc->rawEntropy(12, 95);
        self::assertEqualsWithDelta(12 * log(95, 2), $entropy, 0.001);
    }

    // ── effectiveEntropy ──────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Sem penalidades: entropia efetiva = entropia bruta')]
    public function effectiveEntropy_noPenalties_equalsRaw(): void
    {
        self::assertSame(50.0, $this->calc->effectiveEntropy(50.0, []));
    }

    #[Test]
    #[TestDox('Penalidade 0.5 divide a entropia pela metade')]
    public function effectiveEntropy_halfPenalty_halvesEntropy(): void
    {
        $penalties = [new Penalty('teste', 0.5)];
        self::assertEqualsWithDelta(25.0, $this->calc->effectiveEntropy(50.0, $penalties), 0.001);
    }

    #[Test]
    #[TestDox('Penalidades múltiplas são multiplicativas')]
    public function effectiveEntropy_multiplePenalties_areMultiplicative(): void
    {
        $penalties = [
            new Penalty('a', 0.5),
            new Penalty('b', 0.4),
        ];
        // 50 × 0.5 × 0.4 = 10.0
        self::assertEqualsWithDelta(10.0, $this->calc->effectiveEntropy(50.0, $penalties), 0.001);
    }

    #[Test]
    #[TestDox('Entropia efetiva nunca é negativa')]
    public function effectiveEntropy_neverNegative(): void
    {
        $penalties = [new Penalty('crusher', 0.0)];
        self::assertGreaterThanOrEqual(0.0, $this->calc->effectiveEntropy(50.0, $penalties));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// DetectedCharsetTest  (Value Object)
// ═════════════════════════════════════════════════════════════════════════════

final class DetectedCharsetTest extends TestCase
{
    // ── poolSize ──────────────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Somente números → pool = 10')]
    public function poolSize_numbersOnly_returns10(): void
    {
        $c = new DetectedCharset(true, false, false, false, false);
        self::assertSame(10, $c->poolSize());
    }

    #[Test]
    #[TestDox('Somente minúsculas → pool = 26')]
    public function poolSize_lowercaseOnly_returns26(): void
    {
        $c = new DetectedCharset(false, true, false, false, false);
        self::assertSame(26, $c->poolSize());
    }

    #[Test]
    #[TestDox('Minúsculas + maiúsculas → pool = 52')]
    public function poolSize_upperAndLower_returns52(): void
    {
        $c = new DetectedCharset(false, true, true, false, false);
        self::assertSame(52, $c->poolSize());
    }

    #[Test]
    #[TestDox('Números + minúsculas → pool = 36 (não 95!)')]
    public function poolSize_numbersAndLower_returns36_notFullAscii(): void
    {
        // CORREÇÃO CRÍTICA: original retornaria 95 (charset "completo") se houvesse símbolo,
        // mas agora numbers+lowercase = 36, evitando superestimação.
        $c = new DetectedCharset(true, true, false, false, false);
        self::assertSame(36, $c->poolSize());
    }

    #[Test]
    #[TestDox('Todos os grupos ASCII → pool = 95')]
    public function poolSize_allAsciiGroups_returns95(): void
    {
        $c = new DetectedCharset(true, true, true, true, false);
        self::assertSame(95, $c->poolSize());
    }

    #[Test]
    #[TestDox('Unicode presente aumenta pool em 1024')]
    public function poolSize_unicode_adds1024(): void
    {
        $c = new DetectedCharset(false, true, false, false, true);
        self::assertSame(26 + 1024, $c->poolSize());
    }

    #[Test]
    #[TestDox('Charset completamente vazio → pool mínimo 1 (evita log(0))')]
    public function poolSize_allFalse_returnsAtLeast1(): void
    {
        $c = new DetectedCharset(false, false, false, false, false);
        self::assertGreaterThanOrEqual(1, $c->poolSize());
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// PasswordStrengthAnalyzerTest
// ═════════════════════════════════════════════════════════════════════════════

final class PasswordStrengthAnalyzerTest extends TestCase
{
    private PasswordStrengthAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new PasswordStrengthAnalyzer();
    }

    // ── detectCharset ─────────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Somente dígitos detecta hasNumbers=true')]
    public function detectCharset_digits_setsHasNumbers(): void
    {
        $c = $this->analyzer->detectCharset('12345');
        self::assertTrue($c->hasNumbers);
        self::assertFalse($c->hasLowercase);
        self::assertFalse($c->hasUppercase);
        self::assertFalse($c->hasAsciiSymbols);
    }

    #[Test]
    #[TestDox('Letras minúsculas detecta hasLowercase=true')]
    public function detectCharset_lowercase_setsHasLowercase(): void
    {
        $c = $this->analyzer->detectCharset('abcdef');
        self::assertTrue($c->hasLowercase);
        self::assertFalse($c->hasNumbers);
    }

    #[Test]
    #[TestDox('Mistura de grupos detecta todos corretamente')]
    public function detectCharset_mixed_setsAllFlags(): void
    {
        $c = $this->analyzer->detectCharset('Abc@9');
        self::assertTrue($c->hasUppercase);
        self::assertTrue($c->hasLowercase);
        self::assertTrue($c->hasNumbers);
        self::assertTrue($c->hasAsciiSymbols);
        self::assertFalse($c->hasUnicode);
    }

    #[Test]
    #[TestDox('Caracteres Unicode detecta hasUnicode=true')]
    public function detectCharset_unicode_setsHasUnicode(): void
    {
        $c = $this->analyzer->detectCharset('こんにちは');
        self::assertTrue($c->hasUnicode);
        self::assertFalse($c->hasNumbers);
        self::assertFalse($c->hasLowercase);
    }

    #[Test]
    #[TestDox('mb_strlen correto: senha com multibyte tem length certo')]
    public function detectCharset_multibyte_lengthIsInCodepoints(): void
    {
        // 'こんにちは' = 5 code points, mas strlen() retornaria 15 bytes em UTF-8
        $password = 'こんにちは';
        self::assertSame(5, mb_strlen($password, 'UTF-8'));
    }

    // ── detectPenalties ───────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Senha na lista de comuns gera penalidade severa')]
    public function detectPenalties_commonPassword_highPenalty(): void
    {
        $penalties = $this->analyzer->detectPenalties('password');
        self::assertNotEmpty($penalties);
        // Factor deve ser muito baixo (≤ 0.1) para senha trivialmente comum
        self::assertLessThanOrEqual(0.1, $penalties[0]->factor);
    }

    #[Test]
    #[TestDox('Senha curta (< 8 chars) gera penalidade')]
    public function detectPenalties_shortPassword_hasPenalty(): void
    {
        $penalties = $this->analyzer->detectPenalties('Ab1!');
        $reasons   = array_column($penalties, 'reason');
        // Pelo menos uma penalidade deve mencionar comprimento
        $hasLengthPenalty = array_filter($reasons, fn($r) => str_contains($r, 'mínimo') || str_contains($r, 'omprim'));
        self::assertNotEmpty($hasLengthPenalty);
    }

    #[Test]
    #[TestDox('Alta repetição de caracteres gera penalidade')]
    public function detectPenalties_repeatedChars_hasPenalty(): void
    {
        $penalties = $this->analyzer->detectPenalties('aaaaaaaaaa');
        $reasons   = array_column($penalties, 'reason');
        $hasRepeat = array_filter($reasons, fn($r) => str_contains($r, 'epeti'));
        self::assertNotEmpty($hasRepeat);
    }

    #[Test]
    #[TestDox('Sequência numérica "12345" gera penalidade')]
    public function detectPenalties_numericSequence_hasPenalty(): void
    {
        $penalties = $this->analyzer->detectPenalties('Pass12345!');
        $reasons   = array_column($penalties, 'reason');
        $hasSeq    = array_filter($reasons, fn($r) => str_contains($r, 'equência numérica'));
        self::assertNotEmpty($hasSeq);
    }

    #[Test]
    #[TestDox('Sequência decrescente "9876" também é detectada')]
    public function detectPenalties_descendingNumericSequence_hasPenalty(): void
    {
        $penalties = $this->analyzer->detectPenalties('Pass9876!');
        $reasons   = array_column($penalties, 'reason');
        $hasSeq    = array_filter($reasons, fn($r) => str_contains($r, 'equência numérica'));
        self::assertNotEmpty($hasSeq);
    }

    #[Test]
    #[TestDox('Sequência alfabética "abcd" gera penalidade')]
    public function detectPenalties_alphabeticSequence_hasPenalty(): void
    {
        $penalties = $this->analyzer->detectPenalties('Xabcdef9!');
        $reasons   = array_column($penalties, 'reason');
        $hasSeq    = array_filter($reasons, fn($r) => str_contains($r, 'alfabética'));
        self::assertNotEmpty($hasSeq);
    }

    #[Test]
    #[TestDox('Padrão de teclado "qwerty" gera penalidade')]
    public function detectPenalties_keyboardPattern_hasPenalty(): void
    {
        $penalties = $this->analyzer->detectPenalties('Qwerty123!');
        $reasons   = array_column($penalties, 'reason');
        $hasKb     = array_filter($reasons, fn($r) => str_contains($r, 'teclado'));
        self::assertNotEmpty($hasKb);
    }

    #[Test]
    #[TestDox('Senha forte e aleatória não recebe penalidades')]
    public function detectPenalties_strongRandom_noPenalties(): void
    {
        // Senha propositalmente forte, sem padrões detectáveis
        $penalties = $this->analyzer->detectPenalties('Tr0ub4dor&3!xK#9');
        self::assertEmpty($penalties);
    }

    // ── entropyToScore ────────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Entropia 0 → score 0')]
    public function entropyToScore_zero_returns0(): void
    {
        self::assertSame(0, $this->analyzer->entropyToScore(0.0));
    }

    #[Test]
    #[TestDox('Entropia 80+ → score próximo de 100')]
    public function entropyToScore_highEntropy_nearMax(): void
    {
        $score = $this->analyzer->entropyToScore(100.0);
        self::assertGreaterThanOrEqual(95, $score);
        self::assertLessThanOrEqual(100, $score);
    }

    #[Test]
    #[TestDox('Score está sempre no intervalo 0–100')]
    #[DataProvider('entropyProvider')]
    public function entropyToScore_alwaysInRange(float $entropy): void
    {
        $score = $this->analyzer->entropyToScore($entropy);
        self::assertGreaterThanOrEqual(0, $score);
        self::assertLessThanOrEqual(100, $score);
    }

    public static function entropyProvider(): array
    {
        return [
            'zero'        => [0.0],
            'very low'    => [5.0],
            'low'         => [20.0],
            'medium-low'  => [30.0],
            'medium'      => [50.0],
            'high'        => [70.0],
            'very high'   => [100.0],
            'extreme'     => [256.0],
        ];
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// BruteforceEstimatorTest
// ═════════════════════════════════════════════════════════════════════════════

final class BruteforceEstimatorTest extends TestCase
{
    private BruteforceEstimator $estimator;

    protected function setUp(): void
    {
        $this->estimator = new BruteforceEstimator();
    }

    #[Test]
    #[TestDox('Entropia muito baixa → tempo em ms (online) e ms/segundos (GPU)')]
    public function estimate_veryLowEntropy_fastCrack(): void
    {
        $result = $this->estimator->estimate(10.0, AttackScenario::offlineFast());
        // Com GPU a 100B/s e H=10, keyspace=1024 → ~10 nanosegundos
        self::assertStringContainsString('ms', $result['time']);
    }

    #[Test]
    #[TestDox('Entropia alta → tempo astronômico (décadas/milênios)')]
    public function estimate_highEntropy_longTime(): void
    {
        // H=128 bits, ataque online 100/s → enorme
        $result = $this->estimator->estimate(128.0, AttackScenario::online());
        // Não deve dizer "ms" nem "segundos" nem "minutos"
        self::assertStringNotContainsStringIgnoringCase('ms', $result['time']);
        self::assertStringNotContainsStringIgnoringCase('segundo', $result['time']);
    }

    #[Test]
    #[TestDox('Resultado contém campos obrigatórios')]
    public function estimate_resultHasRequiredFields(): void
    {
        $result = $this->estimator->estimate(50.0, AttackScenario::offlineSlow());
        self::assertArrayHasKey('scenario',    $result);
        self::assertArrayHasKey('description', $result);
        self::assertArrayHasKey('time',        $result);
        self::assertArrayHasKey('raw_seconds', $result);
    }

    #[Test]
    #[TestDox('Ataque online é mais lento que ataque GPU (mesmo H)')]
    public function estimate_onlineSlowerThanGpu(): void
    {
        $online = $this->estimator->estimate(40.0, AttackScenario::online());
        $gpu    = $this->estimator->estimate(40.0, AttackScenario::offlineFast());

        self::assertGreaterThan($gpu['raw_seconds'], $online['raw_seconds']);
    }

    #[Test]
    #[TestDox('Entropia extrema (>200 bits) não gera INF nem exceção')]
    public function estimate_extremeEntropy_noInfOrException(): void
    {
        $result = $this->estimator->estimate(300.0, AttackScenario::offlineFast());
        self::assertIsString($result['time']);
        self::assertStringNotContainsStringIgnoringCase('INF', $result['time']);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SeverityClassifierTest
// ═════════════════════════════════════════════════════════════════════════════

final class SeverityClassifierTest extends TestCase
{
    private SeverityClassifier $classifier;

    protected function setUp(): void
    {
        $this->classifier = new SeverityClassifier();
    }

    #[Test]
    #[TestDox('Entropia 0 → nível CRITICAL')]
    public function classify_zeroEntropy_isCritical(): void
    {
        self::assertSame('CRITICAL', $this->classifier->classify(0.0)['level']);
    }

    #[Test]
    #[TestDox('Entropia 34 (abaixo de 35) → CRITICAL')]
    public function classify_belowCriticalThreshold_isCritical(): void
    {
        self::assertSame('CRITICAL', $this->classifier->classify(34.9)['level']);
    }

    #[Test]
    #[TestDox('Entropia 35 (limiar) → MEDIUM')]
    public function classify_atCriticalThreshold_isMedium(): void
    {
        self::assertSame('MEDIUM', $this->classifier->classify(35.0)['level']);
    }

    #[Test]
    #[TestDox('Entropia 59.9 → MEDIUM')]
    public function classify_belowMediumThreshold_isMedium(): void
    {
        self::assertSame('MEDIUM', $this->classifier->classify(59.9)['level']);
    }

    #[Test]
    #[TestDox('Entropia 60 (limiar) → STRONG')]
    public function classify_atStrongThreshold_isStrong(): void
    {
        self::assertSame('STRONG', $this->classifier->classify(60.0)['level']);
    }

    #[Test]
    #[TestDox('Resultado contém level, color e label')]
    public function classify_resultHasRequiredKeys(): void
    {
        $result = $this->classifier->classify(50.0);
        self::assertArrayHasKey('level', $result);
        self::assertArrayHasKey('color', $result);
        self::assertArrayHasKey('label', $result);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SecCheckAnalyzerTest  (integração das peças – testes de caminho completo)
// ═════════════════════════════════════════════════════════════════════════════

final class SecCheckAnalyzerTest extends TestCase
{
    private SecCheckAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = SecCheckFactory::create();
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Senha vazia retorna score 0 e nível CRITICAL')]
    public function analyze_emptyPassword_criticalAndZeroScore(): void
    {
        $result = $this->analyzer->analyze('');
        self::assertSame(0, $result['strength']['score']);
        self::assertSame('CRITICAL', $result['strength']['severity_level']);
        self::assertSame(0, $result['input']['length']);
    }

    #[Test]
    #[TestDox('Senha vazia retorna recomendação de preenchimento')]
    public function analyze_emptyPassword_hasRecommendation(): void
    {
        $result = $this->analyzer->analyze('');
        self::assertNotEmpty($result['recommendations']);
    }

    // ── Senhas críticas ───────────────────────────────────────────────────────

    #[Test]
    #[TestDox('"123" → CRITICAL com score baixo')]
    public function analyze_threeDigits_isCritical(): void
    {
        $result = $this->analyzer->analyze('123');
        self::assertSame('CRITICAL', $result['strength']['severity_level']);
        self::assertLessThan(25, $result['strength']['score']);
    }

    #[Test]
    #[TestDox('"password" → CRITICAL (comum)')]
    public function analyze_commonPassword_isCritical(): void
    {
        $result = $this->analyzer->analyze('password');
        self::assertSame('CRITICAL', $result['strength']['severity_level']);
    }

    #[Test]
    #[TestDox('"password" tem entropia efetiva menor que bruta (penalidade aplicada)')]
    public function analyze_commonPassword_effectiveLowerThanRaw(): void
    {
        $result = $this->analyzer->analyze('password');
        self::assertLessThan(
            $result['entropy']['raw_bits'],
            $result['entropy']['effective_bits'],
        );
    }

    // ── Correção crítica: soma de charset ────────────────────────────────────

    #[Test]
    #[TestDox('CORREÇÃO: "abc123" não infla charset para 95 (símbolos ausentes)')]
    public function analyze_lettersAndNumbers_charsetNotInflated(): void
    {
        $result = $this->analyzer->analyze('abc123');
        // Pool correto: 26 (lower) + 10 (numbers) = 36
        self::assertSame(36, $result['input']['charset_pool']);
    }

    #[Test]
    #[TestDox('Senha com símbolo inclui grupo ascii_symbols no charset')]
    public function analyze_passwordWithSymbol_hasSymbolGroup(): void
    {
        $result = $this->analyzer->analyze('Abc@1');
        self::assertTrue($result['input']['charset_groups']['ascii_symbols']);
    }

    // ── Senhas fortes ─────────────────────────────────────────────────────────

    #[Test]
    #[TestDox('"Tr0ub4dor&3!xK#9" → STRONG com score ≥ 75')]
    public function analyze_strongPassword_isStrong(): void
    {
        $result = $this->analyzer->analyze('Tr0ub4dor&3!xK#9');
        self::assertSame('STRONG', $result['strength']['severity_level']);
        self::assertGreaterThanOrEqual(75, $result['strength']['score']);
    }

    #[Test]
    #[TestDox('Senha forte não tem penalidades')]
    public function analyze_strongPassword_noPenalties(): void
    {
        $result = $this->analyzer->analyze('Tr0ub4dor&3!xK#9');
        self::assertEmpty($result['entropy']['penalties']);
    }

    // ── Estrutura da resposta ─────────────────────────────────────────────────

    #[Test]
    #[TestDox('Resposta contém todas as seções obrigatórias')]
    public function analyze_result_hasRequiredSections(): void
    {
        $result = $this->analyzer->analyze('TestPass123!');
        self::assertArrayHasKey('meta',              $result);
        self::assertArrayHasKey('input',             $result);
        self::assertArrayHasKey('entropy',           $result);
        self::assertArrayHasKey('strength',          $result);
        self::assertArrayHasKey('attack_simulation', $result);
        self::assertArrayHasKey('recommendations',   $result);
        self::assertArrayHasKey('security_note',     $result);
    }

    #[Test]
    #[TestDox('attack_simulation tem exatamente 3 cenários')]
    public function analyze_attackSimulation_hasThreeScenarios(): void
    {
        $result = $this->analyzer->analyze('TestPass123!');
        self::assertCount(3, $result['attack_simulation']);
    }

    #[Test]
    #[TestDox('analysis_id tem formato SCK2_* e é único entre chamadas')]
    public function analyze_analysisId_uniqueAcrossCalls(): void
    {
        $r1 = $this->analyzer->analyze('TestPass123!');
        $r2 = $this->analyzer->analyze('TestPass123!');
        self::assertStringStartsWith('SCK2_', $r1['meta']['analysis_id']);
        // IDs devem ser diferentes mesmo com a mesma senha
        self::assertNotSame($r1['meta']['analysis_id'], $r2['meta']['analysis_id']);
    }

    #[Test]
    #[TestDox('score é sempre inteiro entre 0 e 100')]
    public function analyze_score_alwaysInValidRange(): void
    {
        foreach (['', '1', 'abc', 'password', 'Abc@123!', str_repeat('X', 50)] as $pwd) {
            $score = $this->analyzer->analyze($pwd)['strength']['score'];
            self::assertGreaterThanOrEqual(0, $score, "Score fora do range para senha: '$pwd'");
            self::assertLessThanOrEqual(100, $score, "Score fora do range para senha: '$pwd'");
        }
    }

    // ── Unicode ───────────────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Senha Unicode não gera exceção e tem comprimento correto')]
    public function analyze_unicodePassword_correctLength(): void
    {
        $pwd    = 'こんにちは世界'; // 7 code points
        $result = $this->analyzer->analyze($pwd);
        self::assertSame(7, $result['input']['length']);
    }

    #[Test]
    #[TestDox('Senha Unicode detecta hasUnicode=true no charset_groups')]
    public function analyze_unicodePassword_flagsUnicode(): void
    {
        $result = $this->analyzer->analyze('こんにちは');
        self::assertTrue($result['input']['charset_groups']['unicode']);
    }

    // ── Recomendações ─────────────────────────────────────────────────────────

    #[Test]
    #[TestDox('Senha sem símbolos recebe recomendação de adicionar símbolos')]
    public function analyze_noSymbols_recommendsAddingSymbols(): void
    {
        $result = $this->analyzer->analyze('AbcDef123456');
        $recs   = implode(' ', $result['recommendations']);
        self::assertStringContainsStringIgnoringCase('símbolo', $recs);
    }

    #[Test]
    #[TestDox('Senha curta recebe recomendação de aumentar comprimento')]
    public function analyze_shortPassword_recommendsLonger(): void
    {
        $result = $this->analyzer->analyze('Ab1!');
        $recs   = implode(' ', $result['recommendations']);
        self::assertStringContainsStringIgnoringCase('caract', $recs);
    }
}