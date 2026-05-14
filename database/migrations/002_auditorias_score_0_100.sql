-- Só execute se a tabela auditorias já existir sem a coluna score_0_100 (instalações antigas).

USE seccheck;

ALTER TABLE auditorias
    ADD COLUMN score_0_100 TINYINT UNSIGNED NOT NULL DEFAULT 0 AFTER entropy_bits;
