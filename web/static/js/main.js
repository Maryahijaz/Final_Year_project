// ─── Theme Toggle ─────────────────────────────
function toggleTheme() {
    const html = document.documentElement;
    const btn = document.querySelector('.theme-toggle');
    if (html.getAttribute('data-theme') === 'dark') {
        html.setAttribute('data-theme', 'light');
        btn.textContent = '☀️';
        localStorage.setItem('theme', 'light');
    } else {
        html.setAttribute('data-theme', 'dark');
        btn.textContent = '🌙';
        localStorage.setItem('theme', 'dark');
    }
}

// Load saved theme
window.addEventListener('load', () => {
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    const btn = document.querySelector('.theme-toggle');
    if (btn) btn.textContent = saved === 'dark' ? '🌙' : '☀️';
});

// ─── Chat Functions ───────────────────────────
function handleKey(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}

function quickQuery(text) {
    const input = document.getElementById('promptInput');
    if (input) {
        input.value = text;
        updateCharCount();
        sendMessage();
    }
}

function updateCharCount() {
    const input = document.getElementById('promptInput');
    const counter = document.getElementById('charCount');
    if (input && counter) {
        counter.textContent = `${input.value.length} / 2000`;
    }
}

// Auto resize textarea
document.addEventListener('DOMContentLoaded', () => {
    const textarea = document.getElementById('promptInput');
    if (textarea) {
        textarea.addEventListener('input', () => {
            textarea.style.height = 'auto';
            textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
            updateCharCount();
        });
    }
});

function addMessage(role, content, isError = false) {
    const messages = document.getElementById('chatMessages');
    if (!messages) return;

    const div = document.createElement('div');
    div.className = `message ${role} ${isError ? 'error' : ''}`;

    let avatar = '';
    if (role === 'user') {
        avatar = '<div class="message-avatar">👤</div>';
    } else if (role === 'assistant') {
        avatar = '<div class="message-avatar">🛡️</div>';
    }

    // Format markdown-like content
    const formatted = content
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`(.*?)`/g, '<code style="background:var(--bg3);padding:2px 6px;border-radius:4px;font-size:13px">$1</code>')
        .replace(/\n/g, '<br>');

    div.innerHTML = `
        ${avatar}
        <div class="message-content">${formatted}</div>
    `;

    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
}

function addTyping() {
    const messages = document.getElementById('chatMessages');
    if (!messages) return;

    const div = document.createElement('div');
    div.className = 'message assistant';
    div.id = 'typingIndicator';
    div.innerHTML = `
        <div class="message-avatar">🛡️</div>
        <div class="message-content">
            <div class="typing">
                <span></span><span></span><span></span>
            </div>
        </div>
    `;
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
}

function removeTyping() {
    const typing = document.getElementById('typingIndicator');
    if (typing) typing.remove();
}

async function sendMessage() {
    const input = document.getElementById('promptInput');
    const sendBtn = document.getElementById('sendBtn');
    if (!input || !sendBtn) return;

    const prompt = input.value.trim();
    if (!prompt) return;

    // Add user message
    addMessage('user', prompt);
    input.value = '';
    input.style.height = 'auto';
    updateCharCount();

    // Disable button
    sendBtn.disabled = true;
    addTyping();

    try {
        const response = await fetch('/api/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt })
        });

        removeTyping();

        if (response.status === 401) {
            window.location.href = '/login';
            return;
        }

        const data = await response.json();

        if (response.ok) {
            addMessage('assistant', data.answer);
        } else {
            addMessage('assistant', data.error || 'An error occurred', true);
        }

    } catch (error) {
        removeTyping();
        addMessage('assistant', '❌ Connection error. Please try again.', true);
    } finally {
        sendBtn.disabled = false;
        input.focus();
    }
}

// ─── Stats from Monitoring ────────────────────
async function refreshStats() {
    try {
        const res = await fetch('/api/monitoring/stats');
        if (res.ok) {
            const data = await res.json();
            document.getElementById('mcpTotal').textContent = data.total_requests || 0;
            document.getElementById('mcpBlocked').textContent = data.total_blocked || 0;
            document.getElementById('mcpAttacks').textContent = data.total_security_events || 0;
            document.getElementById('mcpSuccess').textContent = (data.success_rate || 0) + '%';
        }
    } catch (e) {
        console.log('Monitoring unavailable');
    }
}

// تحديث تلقائي كل 30 ثانية
setInterval(refreshStats, 30000);
window.addEventListener('load', () => {
    refreshStats();
});
