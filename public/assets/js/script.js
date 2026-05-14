(function () {
    'use strict';

    const form = document.getElementById('password-form');
    const input = document.getElementById('password-input');
    const toggleBtn = document.getElementById('toggle-visibility');
    const toggleIcon = document.getElementById('toggle-visibility-icon');
    const submitBtn = document.getElementById('submit-btn');
    const feedback = document.getElementById('feedback-area');
    const errorAlert = document.getElementById('error-alert');
    const scoreBar = document.getElementById('score-bar');
    const scoreLabel = document.getElementById('score-label');
    const severityText = document.getElementById('severity-text');
    const entropyText = document.getElementById('entropy-text');
    const timeEstimate = document.getElementById('time-estimate');
    const recommendationList = document.getElementById('recommendation-list');
    const securityNote = document.getElementById('security-note');

    function hideError() {
        errorAlert.classList.add('d-none');
        errorAlert.textContent = '';
    }

    function showError(message) {
        errorAlert.textContent = message;
        errorAlert.classList.remove('d-none');
    }

    function severityClass(level) {
        switch (level) {
            case 'CRITICAL':
                return 'text-critical';
            case 'MEDIUM':
                return 'text-medium';
            case 'STRONG':
                return 'text-strong';
            default:
                return 'text-secondary';
        }
    }

    function applySeverityColor(colorHex) {
        if (!colorHex) return;
        document.documentElement.style.setProperty('--sec-dynamic-accent', colorHex);
        scoreBar.style.backgroundColor = colorHex;
        scoreBar.style.color = '#031018';
    }

    function renderAttackTimes(attackSimulation) {
        if (!Array.isArray(attackSimulation) || attackSimulation.length === 0) {
            return 'Sem simulação disponível para esta entrada.';
        }
        return attackSimulation
            .map(function (row) {
                const name = row.scenario ?? 'cenário';
                const t = row.time ?? '—';
                const desc = row.description ? ' — ' + row.description : '';
                return '<div class="mb-1"><span class="text-info">' + escapeHtml(name) + '</span>: ' + escapeHtml(t) + escapeHtml(desc) + '</div>';
            })
            .join('');
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function renderRecommendations(items) {
        recommendationList.innerHTML = '';
        if (!Array.isArray(items) || items.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'Nenhuma recomendação adicional.';
            recommendationList.appendChild(li);
            return;
        }
        items.forEach(function (text) {
            const li = document.createElement('li');
            li.textContent = text;
            recommendationList.appendChild(li);
        });
    }

    toggleBtn.addEventListener('click', function () {
        const isPwd = input.getAttribute('type') === 'password';
        input.setAttribute('type', isPwd ? 'text' : 'password');
        toggleIcon.classList.toggle('bi-eye', !isPwd);
        toggleIcon.classList.toggle('bi-eye-slash', isPwd);
    });

    form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        hideError();
        feedback.classList.add('d-none');
        securityNote.classList.add('d-none');

        const password = input.value;
        submitBtn.disabled = true;

        fetch('api/validar-senha.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                Accept: 'application/json',
            },
            body: JSON.stringify({ password: password }),
        })
            .then(function (res) {
                return res.text().then(function (text) {
                    let data;
                    try {
                        data = text ? JSON.parse(text) : {};
                    } catch (ignore) {
                        var preview = text.replace(/\s+/g, ' ').slice(0, 280);
                        throw new Error(
                            'O servidor não devolveu JSON (HTTP ' +
                                res.status +
                                '). ' +
                                'Costuma ser erro de PHP ou arquivo da API em falta. ' +
                                'Prévia: ' +
                                preview
                        );
                    }
                    return { ok: res.ok, status: res.status, data: data };
                });
            })
            .then(function (payload) {
                if (!payload.ok) {
                    const msg =
                        (payload.data && payload.data.error) ||
                        'Erro ' + payload.status + ' ao contactar o servidor.';
                    showError(msg);
                    return;
                }
                const d = payload.data;
                const strength = d.strength || {};
                const entropy = d.entropy || {};
                const color = strength.severity_color || '#22d3ee';
                const level = strength.severity_level || '';
                const label = strength.severity_label || '—';
                const score = typeof strength.score === 'number' ? strength.score : 0;

                scoreBar.style.width = score + '%';
                scoreBar.setAttribute('aria-valuenow', String(score));
                scoreLabel.textContent = String(score);
                scoreLabel.style.color = color;
                applySeverityColor(color);

                severityText.textContent = label + ' (' + level + ')';
                severityText.className = 'fs-5 fw-semibold mt-1 ' + severityClass(level);
                severityText.style.color = color;

                const eff = entropy.effective_bits;
                entropyText.textContent =
                    typeof eff === 'number' ? eff.toFixed(2) + ' bits' : '—';
                entropyText.style.color = color;

                timeEstimate.innerHTML = renderAttackTimes(d.attack_simulation);
                renderRecommendations(d.recommendations);

                if (d.security_note) {
                    securityNote.textContent = d.security_note;
                    securityNote.classList.remove('d-none');
                }

                feedback.classList.remove('d-none');
            })
            .catch(function (err) {
                showError(
                    err && err.message
                        ? err.message
                        : 'Falha de rede ou resposta inválida do servidor.'
                );
            })
            .finally(function () {
                submitBtn.disabled = false;
            });
    });
})();
