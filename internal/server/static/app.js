// tokd browser helpers: passkey ceremonies and confirmation forms.
const b64u = {
  dec: s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0)),
  enc: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
};

function credJSON(c) {
  const r = c.response, out = { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, response: { clientDataJSON: b64u.enc(r.clientDataJSON) } };
  if (r.attestationObject) {
    out.response.attestationObject = b64u.enc(r.attestationObject);
    if (r.getTransports) out.response.transports = r.getTransports();
  } else {
    out.response.authenticatorData = b64u.enc(r.authenticatorData);
    out.response.signature = b64u.enc(r.signature);
    if (r.userHandle) out.response.userHandle = b64u.enc(r.userHandle);
  }
  return out;
}

async function getJSON(url) {
  const r = await fetch(url, { credentials: 'same-origin' });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

async function postJSON(url, body) {
  const r = await fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

async function passkeyProof() {
  const { ceremony, options } = await getJSON('/auth/passkey/begin');
  const pk = options.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  (pk.allowCredentials || []).forEach(c => c.id = b64u.dec(c.id));
  const cred = await navigator.credentials.get({ publicKey: pk });
  return { ceremony, credential: credJSON(cred) };
}

async function registerPasskey(name) {
  const { ceremony, options } = await getJSON('/passkeys/begin');
  const pk = options.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  pk.user.id = b64u.dec(pk.user.id);
  (pk.excludeCredentials || []).forEach(c => c.id = b64u.dec(c.id));
  const cred = await navigator.credentials.create({ publicKey: pk });
  await postJSON('/passkeys/finish', { ceremony, name, credential: credJSON(cred) });
}

// <form data-confirm="/endpoint" data-done="/redirect">: buttons with data-method=passkey|password|deny.
// Named inputs are sent as JSON; checkboxes with the same name become an array, number-ish selects become ints.
function collect(form) {
  const out = {};
  for (const el of form.elements) {
    if (!el.name || el.name === 'password') continue;
    if (el.type === 'checkbox') { (out[el.name] ||= []); if (el.checked) out[el.name].push(el.value); }
    else if (el.type === 'radio') { if (el.checked) out[el.name] = +el.value || el.value; }
    else out[el.name] = el.dataset.int !== undefined ? parseInt(el.value, 10) : el.value;
  }
  return out;
}

document.addEventListener('click', async ev => {
  const btn = ev.target.closest('button[data-method]');
  if (!btn) return;
  const form = btn.closest('form[data-confirm]');
  if (!form) return;
  ev.preventDefault();
  const msg = form.querySelector('.msg');
  const show = (t, ok) => { if (msg) { msg.textContent = t; msg.className = 'msg ' + (ok ? 'ok' : 'err'); } };
  try {
    const body = collect(form);
    const m = btn.dataset.method;
    if (m === 'passkey') Object.assign(body, await passkeyProof());
    else if (m === 'password') body.password = form.querySelector('[name=password]').value;
    else if (m === 'deny') body.deny = true;
    const res = await postJSON(form.dataset.confirm, body);
    show(form.dataset.okText || res.ok, true);
    form.querySelectorAll('button').forEach(b => b.disabled = true);
    if (form.dataset.done) location.href = form.dataset.done;
    // Tabs opened by tok (one-page history) may close themselves; browsers ignore this otherwise.
    if (form.dataset.close !== undefined) setTimeout(() => {
      window.close();
      setTimeout(() => show(msg.textContent + ' You can close this tab.', true), 300);
    }, 1500);
  } catch (e) { show(e.message, false); }
});

// Reveal / copy buttons on the token list.
document.addEventListener('click', async ev => {
  const btn = ev.target.closest('button[data-reveal]');
  if (!btn) return;
  const cell = document.getElementById('v' + btn.dataset.reveal);
  if (btn.dataset.shown) { cell.textContent = cell.dataset.masked; delete btn.dataset.shown; btn.textContent = 'Show'; return; }
  try {
    const { value } = await postJSON('/tokens/' + btn.dataset.reveal + '/reveal', {});
    cell.dataset.masked = cell.textContent; cell.textContent = value; btn.dataset.shown = 1; btn.textContent = 'Hide';
  } catch (e) { alert(e.message); }
});

document.addEventListener('click', async ev => {
  const btn = ev.target.closest('button[data-copy]');
  if (!btn) return;
  try {
    const { value } = await postJSON('/tokens/' + btn.dataset.copy + '/reveal', {});
    await navigator.clipboard.writeText(value);
    btn.textContent = 'Copied'; setTimeout(() => btn.textContent = 'Copy', 1500);
  } catch (e) { alert(e.message); }
});

document.addEventListener('click', async ev => {
  const btn = ev.target.closest('button[data-register]');
  if (!btn) return;
  ev.preventDefault();
  const name = document.getElementById('pkname').value;
  try { await registerPasskey(name); location.reload(); } catch (e) { alert('Passkey registration failed: ' + e.message); }
});

// Enter in a password field presses the matching button.
document.addEventListener('keydown', ev => {
  if (ev.key !== 'Enter' || ev.target.name !== 'password') return;
  const btn = ev.target.closest('form[data-confirm]')?.querySelector('button[data-method=password]');
  if (btn) { ev.preventDefault(); btn.click(); }
});

// Names: same rules as normalizeName in web.go (plus accent stripping: Žalias -> zalias), applied when the field loses focus.
const normalizeName = s => s.normalize('NFD').replace(/\p{M}/gu, '').trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '_').replace(/^[._-]+|[._-]+$/g, '').slice(0, 64).replace(/[._-]+$/, '');
document.addEventListener('change', ev => {
  if (ev.target.matches('input[data-normalize]')) ev.target.value = normalizeName(ev.target.value);
});

// Expiry quick picks: offset from the date added (data-base) on existing tokens, from today on new ones.
document.addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-expire]');
  if (!btn) return;
  const input = document.getElementById('f-exp'), x = btn.dataset.expire;
  if (!x) { input.value = ''; return; }
  const d = input.dataset.base ? new Date(input.dataset.base + 'T00:00') : new Date();
  const n = parseInt(x, 10);
  if (x.endsWith('d')) d.setDate(d.getDate() + n);
  else if (x.endsWith('m')) d.setMonth(d.getMonth() + n);
  else d.setFullYear(d.getFullYear() + n);
  input.value = d.toLocaleDateString('sv-SE'); // YYYY-MM-DD in local time
});

// Context dialogs in event tables; a click on the backdrop closes them.
document.addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-dialog]');
  if (btn) btn.nextElementSibling.showModal();
  else if (ev.target.tagName === 'DIALOG') ev.target.close();
});

// Theme switch: "auto" follows the OS (no data-theme), light/dark are remembered in localStorage.
function markTheme() {
  const t = document.documentElement.dataset.theme || 'auto';
  document.querySelectorAll('[data-theme-set]').forEach(b => b.setAttribute('aria-pressed', b.dataset.themeSet === t));
}
document.addEventListener('click', ev => {
  const btn = ev.target.closest('button[data-theme-set]');
  if (!btn) return;
  const t = btn.dataset.themeSet;
  if (t === 'auto') { delete document.documentElement.dataset.theme; localStorage.removeItem('theme'); }
  else { document.documentElement.dataset.theme = t; localStorage.setItem('theme', t); }
  markTheme();
});
markTheme();
