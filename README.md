# SecCheck 🔐

![PHP](https://img.shields.io/badge/PHP-8.1%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)
![SOLID](https://img.shields.io/badge/Architecture-SOLID-success?style=for-the-badge)
![PHPUnit](https://img.shields.io/badge/Tested%20With-PHPUnit-366488?style=for-the-badge&logo=php&logoColor=white)

---

# 📖 Descrição

O **SecCheck** é uma biblioteca *Enterprise-Grade* desenvolvida em **PHP 8.1+** para análise avançada de força de senhas, cálculo de entropia e estimativa de resistência contra ataques de força bruta.

O projeto foi desenvolvido utilizando conceitos modernos de engenharia de software, incluindo:

- SOLID
- Value Objects
- Dependency Injection
- Strict Types
- Arquitetura orientada a domínio
- Testes automatizados com PHPUnit

Além do cálculo tradicional de entropia, o SecCheck aplica heurísticas inteligentes para identificar padrões inseguros e estimar a força real da senha em cenários modernos de ataque.

Este projeto foi desenvolvido como parte de um trabalho acadêmico/TCC do curso de **Análise e Desenvolvimento de Sistemas**.

---

# 🚀 Funcionalidades Principais

- ✅ Cálculo de entropia bruta da senha
- ✅ Cálculo de entropia efetiva com penalidades heurísticas
- ✅ Detecção automática do charset utilizado
- ✅ Suporte completo a Unicode e caracteres multibyte
- ✅ Identificação de padrões de teclado
  - `qwerty`
  - `123456`
  - sequências lineares
- ✅ Detecção de repetições de caracteres
- ✅ Detecção de palavras de dicionário
- ✅ Estimativa de tempo de quebra:
  - Online Attack
  - Offline Slow Hash
  - Offline Fast Hash
- ✅ Arquitetura desacoplada e extensível
- ✅ Tipagem estrita (`declare(strict_types=1)`)
- ✅ Cobertura de testes com PHPUnit
- ✅ Código orientado a boas práticas de segurança

---

# 📂 Estrutura de Arquivos

```text
SecCheck/
│
├── src/
│   └── SecCheck.php
│
├── tests/
│   ├── EntropyCalculatorTest.php
│   ├── PasswordAnalyzerTest.php
│   └── HeuristicsTest.php
│
├── vendor/
├── composer.json
├── phpunit.xml
└── README.md
```

---

# ⚙️ Instalação e Como Usar

## Requisitos

- PHP 8.1+
- Composer
- Extensão `mbstring`

---

## Instalação

```bash
composer install
```

---

## Exemplo de Uso

```php
<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use SecCheck\Factory\SecCheckFactory;

$secCheck = SecCheckFactory::create();

$result = $secCheck->analyze('MinhaSenha@2026');

echo "Senha: {$result->password}\n";
echo "Charset Detectado: {$result->charset}\n";
echo "Entropia Bruta: {$result->rawEntropy} bits\n";
echo "Entropia Efetiva: {$result->effectiveEntropy} bits\n";
echo "Força: {$result->strength}\n";

echo "\n=== Tempo Estimado de Quebra ===\n";

echo "Online Attack: {$result->crackTime->online}\n";
echo "Offline Slow Hash: {$result->crackTime->offlineSlow}\n";
echo "Offline Fast Hash: {$result->crackTime->offlineFast}\n";
```

---

## ⚠️ Aviso Importante

> Esta biblioteca foi projetada para ser utilizada como uma aplicação PHP estruturada.
>
> **Não é recomendado copiar e colar o código diretamente dentro do arquivo `functions.php` do WordPress ou em ambientes sem autoload/Composer.**
>
> Utilize corretamente o autoload PSR-4 e a estrutura orientada a objetos do projeto.

---

# 🧪 Testes

O projeto possui uma suíte completa de testes automatizados utilizando PHPUnit.

## Rodar todos os testes

```bash
vendor/bin/phpunit
```

---

## Rodar com cobertura

```bash
vendor/bin/phpunit --coverage-text
```

---

# 🔒 Segurança

O **SecCheck** apenas realiza análise de força e entropia da senha em memória.

A biblioteca:

- ❌ NÃO armazena senhas
- ❌ NÃO criptografa senhas automaticamente
- ❌ NÃO substitui mecanismos reais de autenticação

Para armazenamento seguro de senhas, utilize sempre:

```php
password_hash($password, PASSWORD_ARGON2ID);
```

Também é recomendado:

- Utilizar salts automáticos do PHP
- Configurar rate limiting
- Implementar MFA/2FA
- Seguir as recomendações do NIST e OWASP

---

# 📚 Referências

- NIST SP 800-63B — Digital Identity Guidelines
- OWASP Password Storage Cheat Sheet
- Dropbox zxcvbn Password Strength Estimator
- Shannon Entropy Theory
- OWASP Authentication Cheat Sheet

---

# 👨‍💻 Autor

Projeto desenvolvido para fins acadêmicos/TCC no curso de **Análise e Desenvolvimento de Sistemas**.

---

# 📄 Licença

Este projeto é disponibilizado apenas para fins educacionais e acadêmicos.
