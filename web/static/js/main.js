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

    addMessage('user', prompt);
    input.value = '';
    input.style.height = 'auto';
    updateCharCount();

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
            return;
        }

        // ─── Attack Detection Messages ───────────────
        const detail = data.detail || data.error || '';

        if (response.status === 400) {
            let attackMsg = '';

            if (detail.includes('RAG_POISONING')) {
                attackMsg = '☣️ RAG Poisoning Attack Detected!\n\nYou attempted to manipulate the AI knowledge base by overriding its context. TrustZAI Zero Trust has blocked this request.';
            } else if (detail.includes('RAG_DATA_EXTRACTION')) {
                attackMsg = '📤 Data Extraction Attack Detected!\n\nYou attempted to extract all documents from the database. TrustZAI Zero Trust has blocked this request.';
            } else if (detail.includes('RAG_CONTEXT_INJECTION')) {
                attackMsg = '💉 Context Injection Attack Detected!\n\nYou attempted to inject malicious context into the AI pipeline. TrustZAI Zero Trust has blocked this request.';
            } else if (detail.includes('RAG_FLOODING')) {
                attackMsg = '🌊 RAG Flooding Attack Detected!\n\nExcessive prompt length detected. This may indicate a flooding attempt. TrustZAI Zero Trust has blocked this request.';
            } else if (detail.includes('Exploit request')) {
                attackMsg = '💀 Exploit Request Detected!\n\nYou attempted to generate exploit code or malware. TrustZAI Zero Trust has blocked this request and logged it as a security event.';
            } else if (detail.includes('Malicious prompt')) {
                attackMsg = '🔴 Prompt Injection Attack Detected!\n\nYou attempted to manipulate AI instructions using known injection techniques. TrustZAI Zero Trust has blocked this request.';
            } else {
                attackMsg = '🚨 Malicious Request Detected!\n\nTrustZAI Zero Trust Security Layer has blocked this request.';
            }

            addMessage('assistant', attackMsg, true);
            return;
        }

        if (response.status === 403) {
            let attackMsg = '';

            if (detail.includes('Privilege escalation')) {
                attackMsg = '⬆️ Privilege Escalation Attack Detected!\n\nYou attempted to claim admin privileges. TrustZAI RBAC has blocked this request and logged it as a security event.';
            } else if (detail.includes('DLP')) {
                attackMsg = '🔒 Data Leakage Prevention Triggered!\n\nThe response contained sensitive data. TrustZAI DLP has filtered and blocked it.';
            } else if (detail.includes('Permission denied')) {
                attackMsg = '🚫 Access Denied!\n\nYour role does not have permission to perform this action. TrustZAI RBAC enforces least privilege.';
            } else {
                attackMsg = '🚫 Access Denied by TrustZAI Zero Trust!';
            }

            addMessage('assistant', attackMsg, true);
            return;
        }

        if (response.status === 429) {
            addMessage('assistant', '🌊 Rate Limit Exceeded!\n\nToo many requests detected. TrustZAI has temporarily blocked your access to prevent API abuse.', true);
            return;
        }

        if (response.status === 423) {
            addMessage('assistant', '🔐 Account Locked!\n\nToo many failed login attempts detected. TrustZAI Brute Force Protection has locked this account.', true);
            return;
        }

        addMessage('assistant', detail || 'An error occurred', true);

    } catch (error) {
        removeTyping();
        addMessage('assistant', '❌ Connection error. Please try again.', true);
    } finally {
        sendBtn.disabled = false;
        input.focus();
    }
}
