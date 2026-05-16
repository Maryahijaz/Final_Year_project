// ─── Theme ────────────────────────────────────
function toggleTheme() {
    const html = document.documentElement;
    const btn = document.querySelector('.theme-toggle');
    const isDark = html.getAttribute('data-theme') === 'dark';
    html.setAttribute('data-theme', isDark ? 'light' : 'dark');
    btn.textContent = isDark ? '☀️' : '🌙';
    localStorage.setItem('theme', isDark ? 'light' : 'dark');
}

window.addEventListener('load', () => {
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    const btn = document.querySelector('.theme-toggle');
    if (btn) btn.textContent = saved === 'dark' ? '🌙' : '☀️';

    if (document.getElementById('totalRequests')) {
        loadStats();
        loadLogs('main', document.querySelector('.tab'));
        setInterval(loadStats, 30000);
    }
});

// ─── Stats ────────────────────────────────────
async function loadStats() {
    const res = await fetch('/api/stats');
    const data = await res.json();

    document.getElementById('totalRequests').textContent = data.total_requests || 0;
    document.getElementById('totalBlocked').textContent = data.total_blocked || 0;
    document.getElementById('totalEvents').textContent = data.total_security_events || 0;
    document.getElementById('successRate').textContent = (data.success_rate || 0) + '%';

    // Attack Types
    const attackDiv = document.getElementById('attackTypes');
    attackDiv.innerHTML = '';
    const attacks = data.attack_types || {};
    if (Object.keys(attacks).length === 0) {
        attackDiv.innerHTML = '<div style="color:var(--text2);font-size:13px">No attacks detected ✅</div>';
    } else {
        for (const [type, count] of Object.entries(attacks)) {
            attackDiv.innerHTML += `
                <div class="attack-item">
                    <span>${type.replace(/_/g, ' ')}</span>
                    <span class="attack-count">${count}</span>
                </div>`;
        }
    }

    // User Activity
    const userDiv = document.getElementById('userActivity');
    userDiv.innerHTML = '';
    const users = data.user_activity || {};
    if (Object.keys(users).length === 0) {
        userDiv.innerHTML = '<div style="color:var(--text2);font-size:13px">No activity yet</div>';
    } else {
        for (const [user, count] of Object.entries(users)) {
            userDiv.innerHTML += `
                <div class="attack-item">
                    <span>👤 ${user}</span>
                    <span class="user-count">${count} requests</span>
                </div>`;
        }
    }
}

// ─── Logs ─────────────────────────────────────
async function loadLogs(type, btn) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    if (btn) btn.classList.add('active');

    const res = await fetch(`/api/logs/${type}`);
    const logs = await res.json();
    const container = document.getElementById('logsContainer');
    container.innerHTML = '';

    if (!logs.length) {
        container.innerHTML = '<div style="color:var(--text2);font-size:13px;padding:12px">No logs found</div>';
        return;
    }

    [...logs].reverse().forEach(log => {
        const time = log.timestamp ? log.timestamp.substring(11, 19) : '';
        const logType = log.type || 'REQUEST';
        let details = '';

        if (logType === 'SECURITY_EVENT') {
            details = `<strong>${log.event_type}</strong> — ${log.details || ''} — User: <strong>${log.username}</strong>`;
        } else if (logType === 'BLOCKED') {
            details = `<strong>${log.reason}</strong> — User: <strong>${log.username}</strong>`;
        } else {
            details = `User: <strong>${log.username}</strong> (${log.role}) — Status: <strong>${log.status}</strong>`;
        }

        container.innerHTML += `
            <div class="log-item ${logType}">
                <span class="log-type ${logType}">${logType.replace('_', ' ')}</span>
                <span class="log-time">${time}</span>
                <span class="log-details">${details}</span>
            </div>`;
    });
}

// ─── Analysis ─────────────────────────────────
async function runAnalysis() {
    const question = document.getElementById('question').value;
    const btn = document.getElementById('analyzeBtn');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');
    const content = document.getElementById('resultContent');

    btn.disabled = true;
    loading.style.display = 'flex';
    result.style.display = 'none';

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question })
        });

        const data = await res.json();
        loading.style.display = 'none';
        result.style.display = 'block';
        document.getElementById('resultTime').textContent = new Date().toLocaleTimeString();

        if (res.ok) {
            content.innerHTML = data.answer
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\n/g, '<br>');
        } else {
            content.textContent = data.error || 'Analysis failed';
        }
    } catch (e) {
        loading.style.display = 'none';
        alert('Error: ' + e.message);
    } finally {
        btn.disabled = false;
    }
}
