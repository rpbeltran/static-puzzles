// Each level page (except level 0) embeds its content encrypted with
// AES-256-GCM, keyed by PBKDF2-SHA256 of the previous level's solution.
// See encryptLevel in levels/level_template.go for the other half.

async function InitLevel() {
    const level = Number(document.body.dataset.level);
    const data_element = document.getElementById('level-data');

    // Dev builds (go run . -dev) ship every level already decrypted.
    if (data_element && !('dev' in document.body.dataset)) {
        const blob = JSON.parse(data_element.textContent);
        const html = await try_decrypt_level(blob, password_from_url());
        if (html === null) {
            document.getElementById('redaction-message').classList.remove('redacted-hide');
            return;
        }
        document.getElementById('level-content').innerHTML = html;
    }

    const header = document.querySelector('#level-content h1');
    if (header && level > 0) {
        document.title = 'Level ' + level + ': ' + header.textContent;
    }

    setup_answer_form(level);
}

// Editing the fragment by hand doesn't reload the page, so do it ourselves.
if (typeof window !== 'undefined') {
    window.addEventListener('hashchange', () => location.reload());
}

function password_from_url() {
    let password = '';
    try {
        password = decodeURIComponent(location.hash.slice(1));
    } catch (e) {
        // malformed escape, treat as wrong password
    }
    if (password === '') {
        // old style links: /level/N?password=...
        password = new URLSearchParams(location.search).get('password');
    }
    return normalize_solution(password);
}

function setup_answer_form(level) {
    const form = document.getElementById('answer-form');
    if (!form) {
        return;
    }
    const button = document.getElementById('level_button');
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const answer = normalize_solution(document.getElementById('password').value);
        button.disabled = true;
        try {
            if (await check_answer(level + 1, answer)) {
                location.href = (level + 1) + '.html#' + encodeURIComponent(answer);
            } else {
                alert('Incorrect');
            }
        } catch (e) {
            console.error(e);
            alert('Something went wrong checking your answer (not a riddle, just a bug).');
        } finally {
            button.disabled = false;
        }
    });
}

// An answer is correct if it decrypts the next level's page.
async function check_answer(next_level, answer) {
    const response = await fetch(next_level + '.html', {cache: 'no-store'});
    if (!response.ok) {
        throw new Error('failed to fetch level ' + next_level + ': ' + response.status);
    }
    const page = new DOMParser().parseFromString(await response.text(), 'text/html');
    const blob = JSON.parse(page.getElementById('level-data').textContent);
    return (await try_decrypt_level(blob, answer)) !== null;
}

// Returns the decrypted level HTML, or null if the password is wrong.
async function try_decrypt_level(blob, password) {
    if (password === '') {
        return null;
    }
    try {
        return await decrypt_level(blob, password);
    } catch (e) {
        // AES-GCM authentication failure, i.e. the wrong key
        if (e.name === 'OperationError') {
            return null;
        }
        throw e;
    }
}

async function decrypt_level(blob, password) {
    const base_key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        {name: 'PBKDF2', salt: base64_to_bytes(blob.salt), iterations: blob.iterations, hash: 'SHA-256'},
        base_key,
        {name: 'AES-GCM', length: 256},
        false,
        ['decrypt']);
    const plaintext = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv: base64_to_bytes(blob.iv)}, key, base64_to_bytes(blob.ciphertext));
    return new TextDecoder().decode(plaintext);
}

function base64_to_bytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// Must match NormalizeSolution in levels/level_template.go.
function normalize_solution(password) {
    if (password == null) {
        return '';
    }
    return password.toLowerCase().replaceAll(' ', '');
}

if (typeof module !== 'undefined') {
    module.exports = {decrypt_level, try_decrypt_level, normalize_solution};
}
