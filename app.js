// app.js

// Precompila l'ID dall'URL: /orologio001 o ?id=orologio001
function preloadIdFromUrl() {
  const params = new URLSearchParams(location.search);
  const qid = params.get('id');
  const pathSeg = location.pathname.replace(/^\/+/, '').trim(); // es. "orologio001"
  const idInput = document.getElementById('id');
  if (idInput) {
    if (qid) idInput.value = qid;
    else if (pathSeg && !pathSeg.includes('.')) idInput.value = pathSeg; // evita index.html
  }
}

async function sblocca(evt) {
  evt.preventDefault(); // <— BLOCCA il submit standard (niente ?id=...&pin=...)
  const id = document.getElementById('id')?.value.trim();
  const pin = document.getElementById('pin')?.value.trim();
  const msg = document.getElementById('msg');

  msg.className = 'message';
  msg.textContent = '';

  if (!id || !pin) {
    msg.textContent = 'Inserisci sia ID che PIN.';
    msg.classList.add('visible','error');
    return;
  }

  try {
    const res = await fetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      body: JSON.stringify({ id, pin })
    });

    const data = await res.json();

    if (!res.ok || !data.ok || !data.token) {
      msg.textContent = '❌ ID/PIN non validi.';
      msg.classList.add('visible','error');
      return;
    }

    // Redirect con token verso l'area sicura
    window.location.href = '/area-sicura.html?token=' + encodeURIComponent(data.token);

  } catch (e) {
    console.error(e);
    msg.textContent = '⚠️ Errore di rete o server.';
    msg.classList.add('visible','error');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  preloadIdFromUrl();
  const form = document.getElementById('unlockForm');
  if (form) form.addEventListener('submit', sblocca);
});
