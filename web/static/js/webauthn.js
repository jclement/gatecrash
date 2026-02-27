// WebAuthn/Passkey helper functions

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlToBuffer(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// Resolve a path relative to the <base> tag
function apiURL(path) {
    const base = document.querySelector('base');
    if (base) {
        return new URL(path, base.href).href;
    }
    return '/' + path;
}

async function registerPasskey() {
    const status = document.getElementById('status');
    const btn = document.getElementById('register-btn');
    btn.disabled = true;
    status.textContent = 'Starting registration...';

    try {
        const optResp = await fetch(apiURL('auth/register/begin'), { method: 'POST' });
        if (!optResp.ok) throw new Error('Failed to get registration options');
        const options = await optResp.json();

        options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
        options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
        if (options.publicKey.excludeCredentials) {
            options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
                ...c,
                id: base64urlToBuffer(c.id)
            }));
        }

        const credential = await navigator.credentials.create(options);

        const body = JSON.stringify({
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
            }
        });

        const finResp = await fetch(apiURL('auth/register/finish'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: body
        });

        if (finResp.ok) {
            status.textContent = 'Passkey registered! Redirecting...';
            status.className = 'is-size-7 mt-2 has-text-success';
            setTimeout(() => window.location.href = apiURL('.'), 1000);
        } else {
            throw new Error('Registration failed');
        }
    } catch (err) {
        status.textContent = 'Error: ' + err.message;
        status.className = 'is-size-7 mt-2 has-text-danger';
        btn.disabled = false;
    }
}

async function authenticatePasskey() {
    const status = document.getElementById('status');
    const btn = document.getElementById('login-btn');
    if (btn) btn.disabled = true;
    status.textContent = 'Starting authentication...';

    try {
        const optResp = await fetch(apiURL('auth/login/begin'), { method: 'POST' });
        if (!optResp.ok) throw new Error('Failed to get authentication options');
        const options = await optResp.json();

        options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
        if (options.publicKey.allowCredentials) {
            options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
                ...c,
                id: base64urlToBuffer(c.id)
            }));
        }

        const assertion = await navigator.credentials.get(options);

        const body = JSON.stringify({
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ?
                    bufferToBase64url(assertion.response.userHandle) : null,
            }
        });

        const finResp = await fetch(apiURL('auth/login/finish'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: body
        });

        if (finResp.ok) {
            status.textContent = 'Authenticated! Redirecting...';
            status.className = 'is-size-7 mt-2 has-text-success';
            setTimeout(() => window.location.href = apiURL('.'), 1000);
        } else {
            throw new Error('Authentication failed');
        }
    } catch (err) {
        status.textContent = 'Error: ' + err.message;
        status.className = 'is-size-7 mt-2 has-text-danger';
        if (btn) btn.disabled = false;
    }
}
