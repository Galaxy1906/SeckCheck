# SecCheck 🔐

![PHP](https://img.shields.io/badge/PHP-8.1%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-00000F?style=for-the-badge&logo=mysql&logoColor=white)
![XAMPP](https://img.shields.io/badge/XAMPP-F37623?style=for-the-badge&logo=xampp&logoColor=white)
![SOLID](https://img.shields.io/badge/Architecture-SOLID-success?style=for-the-badge)
![PHPUnit](https://img.shields.io/badge/Tested%20With-PHPUnit-366488?style=for-the-badge&logo=php&logoColor=white)

---

# 📖 Descrição

O **SecCheck** é uma aplicação web e biblioteca **Enterprise-Grade** desenvolvida em **PHP 8.1+** para análise avançada de força de senhas, cálculo de entropia e estimativa de resistência contra ataques de força bruta.

Além do motor de análise (desenvolvido com princípios **SOLID**, **Value Objects** e **Tipagem Estrita**), o projeto conta com uma **API REST**, uma **Interface de Usuário (Frontend)** interativa e um **Painel Administrativo** para auditoria de testes realizados.

Este projeto foi desenvolvido como parte de um trabalho acadêmico (**TCC**) do curso de **Análise e Desenvolvimento de Sistemas**.

---

# 🚀 Funcionalidades

## 🔍 Núcleo de Análise (Core)

- ✅ Cálculo de **entropia bruta e efetiva** com penalidades heurísticas.
- ✅ Detecção automática do **charset utilizado** (incluindo suporte a Unicode/multibyte).
- ✅ Identificação de padrões inseguros:
  - Sequências de teclado
  - Repetições
  - Palavras de dicionário
- ✅ Estimativa de tempo de quebra para cenários:
  - Online Attack
  - Offline Slow Hash
  - Offline Fast Hash

---

## 🖥️ Aplicação Web & Painel Administrativo

- 🌙 **Frontend Interativo**  
  Interface moderna e responsiva em modo dark para testes de senha em tempo real via API.

- 📊 **Painel Administrativo**  
  Dashboard seguro para visualização de:
  - Métricas de uso
  - Scores médios
  - Histórico de auditorias

- 💾 **Persistência Segura**  
  Registro apenas dos **metadados das análises**.  
  **As senhas NÃO são armazenadas.**

---

# 📂 Estrutura de Arquivos

```text
SecCheck/
│
├── config/                # Configurações de Banco de Dados (PDO)
├── database/              # Schemas SQL, Migrations e Seeds
├── public/                # Raiz do servidor web (Frontend)
│   ├── admin/             # Painel Administrativo
│   ├── api/               # Endpoints da API
│   │   └── validar-senha.php
│   └── assets/            # CSS, JS e imagens
├── src/                   # Núcleo da biblioteca (SecCheck.php)
├── tests/                 # Testes unitários
├── vendor/                # Dependências do Composer
├── composer.json
└── README.md
```

---

# ⚙️ Guia de Instalação para XAMPP

Siga os passos abaixo para rodar o projeto localmente utilizando o **XAMPP**.

---

## 1️⃣ Pré-requisitos

Certifique-se de possuir:

- PHP **8.1 ou superior**
- Apache ativo
- MySQL/MariaDB ativo
- XAMPP instalado

Inicie os módulos **Apache** e **MySQL** no painel de controle do XAMPP.

---

## 2️⃣ Posicionando os Arquivos

Clone ou extraia o projeto para a pasta **htdocs**:

```bash
C:\xampp\htdocs\seccheck
```

---

## 3️⃣ Configuração do Banco de Dados

Abra o **phpMyAdmin**:

```text
http://localhost/phpmyadmin
```

Vá em **Importar** e execute os arquivos SQL **nesta ordem**:

### 1. Criar banco e tabelas

```text
database/schemas/criar_tabelas.sql
```

### 2. Aplicar migrações

```text
database/migrations/002_auditorias_score_0_100.sql
```

### 3. Criar usuário administrador padrão

```text
database/seeds/admin_inicial.sql
```

---

## 4️⃣ Configurando a conexão PHP

Acesse:

```text
config/
```

Duplique:

```text
database.example.php
```

Renomeie para:

```text
database.php
```

Edite com suas credenciais:

```php
<?php

return [
    'dsn'  => 'mysql:host=127.0.0.1;port=3306;dbname=seccheck;charset=utf8mb4',
    'user' => 'root',
    'pass' => '', // Senha em branco no XAMPP padrão
];
```

---

# 🌐 Acessando a Aplicação

Com Apache e MySQL rodando:

## 🔒 Verificador Público

```text
http://localhost/seccheck/public/
```

---

## ⚙️ Painel Administrativo

```text
http://localhost/seccheck/public/admin/
```

### Credenciais padrão

**Usuário:**

```text
admin
```

**Senha:**

```text
password
```

> ⚠️ **Importante:** altere a senha padrão em ambientes de produção.

---

# 🧪 Executando os Testes

Caso tenha o **Composer** instalado:

## Instalar dependências

```bash
composer install
```

## Rodar PHPUnit

```bash
vendor/bin/phpunit
```

---

# 🔐 Aviso de Segurança

O **SecCheck** foi projetado para **não armazenar senhas reais**.

Somente os seguintes metadados podem ser registrados:

- Entropia
- Score
- Tamanho da senha
- Complexidade
- Timestamp da análise

---

## Recomendações para Produção

### Nunca exponha estas pastas:

```text
/config
/database
```

Configure o servidor web para apontar diretamente para:

```text
/public
```

---

### Altere imediatamente:

- Credenciais do banco de dados
- Senha do administrador padrão

---

### Para armazenar senhas reais em outros sistemas, use:

```php
password_hash($password, PASSWORD_ARGON2ID)
```

---

# 📚 Referências Acadêmicas

- **NIST SP 800-63B** — Digital Identity Guidelines
- **OWASP Password Storage Cheat Sheet**
- **Claude Shannon — Entropy Theory**
- **Dropbox zxcvbn Password Strength Estimator**

---

# 🛠️ Stack Tecnológica

- PHP 8.1+
- MySQL / MariaDB
- PDO
- HTML/CSS/JavaScript
- XAMPP
- PHPUnit
- Arquitetura SOLID
- Value Objects
- Tipagem Estrita

---

# 📄 Licença

Projeto desenvolvido para fins **acadêmicos e educacionais** como parte do **Trabalho de Conclusão de Curso (TCC)** em **Análise e Desenvolvimento de Sistemas**.

---

# 👨‍💻 Autor

**Pedro Mauro**  
Desenvolvedor Backend PHP | Infraestrutura & Segurança | ADS
