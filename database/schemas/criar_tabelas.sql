-- SecCheck — esquema inicial (MySQL / MariaDB)
-- Regra: nunca armazenar a senha em texto ou hash de senha de usuário final na tabela de auditorias.

SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE DATABASE IF NOT EXISTS seccheck
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE seccheck;

-- Registros de auditoria das análises (metadados apenas)
CREATE TABLE IF NOT EXISTS auditorias (
    id                  BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    analysis_id         VARCHAR(64)     NOT NULL,
    entropy_bits        FLOAT           NOT NULL COMMENT 'Entropia efetiva (bits) no momento da análise',
    score_0_100         TINYINT UNSIGNED NOT NULL COMMENT 'Score 0–100 devolvido ao utilizador',
    severity            VARCHAR(32)     NOT NULL,
    password_length     INT UNSIGNED    NOT NULL,
    charset_type        VARCHAR(255)    NOT NULL,
    bruteforce_estimate VARCHAR(255)    NOT NULL COMMENT 'Ex.: tempo estimado cenário offline rápido',
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_auditorias_created (created_at),
    INDEX idx_auditorias_analysis (analysis_id)
) ENGINE=InnoDB;

-- Administradores do painel (futuro); senha sempre como password_hash()
CREATE TABLE IF NOT EXISTS usuarios_admin (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    UNIQUE KEY uq_usuarios_admin_username (username)
) ENGINE=InnoDB;

-- Exemplo (descomente após gerar o hash com PHP):
-- INSERT INTO usuarios_admin (username, password_hash) VALUES
-- ('admin', '$2y$10$COLOQUE_AQUI_O_RESULTADO_DE_password_hash');
