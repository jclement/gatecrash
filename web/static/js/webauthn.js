// WebAuthn / passkey helpers.

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

function _status(msg, ok) {
    const el = document.getElementById('status');
    if (!el) return;
    el.textContent = msg;
    el.className = 'text-xs mt-3 ' + (ok === true ? 'text-green-600' : ok === false ? 'text-red-600' : 'text-gray-500');
}

function _safeReturn() {
    const r = new URLSearchParams(window.location.search).get('return');
    return (r && r.startsWith('/') && !r.startsWith('//')) ? r : null;
}

// doRegister runs a passkey registration ceremony against begin/finish URLs.
// On success it navigates to data.redirect (if any) or reloads.
async function doRegister(beginURL, finishURL, btnID) {
    const btn = btnID ? document.getElementById(btnID) : null;
    if (btn) btn.disabled = true;
    _status('Starting…');
    try {
        const optResp = await fetch(beginURL, { method: 'POST' });
        if (!optResp.ok) throw new Error(await optResp.text() || 'failed to start');
        const data = await optResp.json();
        const challengeID = data.challenge_id;
        const pk = data.publicKey;
        pk.challenge = base64urlToBuffer(pk.challenge);
        pk.user.id = base64urlToBuffer(pk.user.id);
        if (pk.excludeCredentials) pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: base64urlToBuffer(c.id) }));

        const cred = await navigator.credentials.create({ publicKey: pk });
        const body = JSON.stringify({
            id: cred.id, rawId: bufferToBase64url(cred.rawId), type: cred.type,
            response: {
                attestationObject: bufferToBase64url(cred.response.attestationObject),
                clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
            },
        });
        const finResp = await fetch(finishURL + '?challenge_id=' + encodeURIComponent(challengeID), {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
        });
        if (!finResp.ok) throw new Error(await finResp.text() || 'registration failed');
        _status('Done! Redirecting…', true);
        let redirect = null;
        try { redirect = (await finResp.json()).redirect; } catch (_) {}
        setTimeout(() => { window.location.href = redirect || window.location.pathname; }, 800);
    } catch (err) {
        _status('Error: ' + (err.message || err), false);
        if (btn) btn.disabled = false;
    }
}

// doLogin runs a usernameless passkey login. On success it navigates to a safe
// ?return= URL, else data.redirect, else "/".
async function doLogin(btnID) {
    const btn = btnID ? document.getElementById(btnID) : null;
    if (btn) btn.disabled = true;
    _status('Starting…');
    try {
        const optResp = await fetch('/auth/login/begin', { method: 'POST' });
        if (!optResp.ok) throw new Error('failed to start');
        const data = await optResp.json();
        const challengeID = data.challenge_id;
        const pk = data.publicKey;
        pk.challenge = base64urlToBuffer(pk.challenge);
        if (pk.allowCredentials) pk.allowCredentials = pk.allowCredentials.map(c => ({ ...c, id: base64urlToBuffer(c.id) }));

        const assertion = await navigator.credentials.get({ publicKey: pk });
        const body = JSON.stringify({
            id: assertion.id, rawId: bufferToBase64url(assertion.rawId), type: assertion.type,
            response: {
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
            },
        });
        const finResp = await fetch('/auth/login/finish?challenge_id=' + encodeURIComponent(challengeID), {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
        });
        if (!finResp.ok) throw new Error('authentication failed');
        _status('Signed in! Redirecting…', true);
        let redirect = null;
        try { redirect = (await finResp.json()).redirect; } catch (_) {}
        setTimeout(() => { window.location.href = _safeReturn() || redirect || '/'; }, 600);
    } catch (err) {
        _status('Error: ' + (err.message || err), false);
        if (btn) btn.disabled = false;
    }
}
