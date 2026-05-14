-- Utilizador admin inicial (altere a senha em produção)
-- Credenciais: utilizador = admin  |  senha = password

USE seccheck;

INSERT INTO usuarios_admin (username, password_hash) VALUES
('admin', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi')
ON DUPLICATE KEY UPDATE username = username;
