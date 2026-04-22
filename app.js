/* =========================================================
   Music Tier List · Spotify
   Client-only app: OAuth PKCE + SortableJS + html2canvas
   No localStorage used — sessionStorage for ephemeral PKCE,
   URL hash carries sharable state.
   ========================================================= */

const TIERS = [
  { id: 'S', color: 'var(--tier-s)' },
  { id: 'A', color: 'var(--tier-a)' },
  { id: 'B', color: 'var(--tier-b)' },
  { id: 'C', color: 'var(--tier-c)' },
  { id: 'D', color: 'var(--tier-d)' },
  { id: 'F', color: 'var(--tier-f)' },
];

const DEFAULT_STYLES = [
  { id: 's-rock',    name: 'Rock',    color: '#ef4444' },
  { id: 's-grunge',  name: 'Grunge',  color: '#78716c' },
  { id: 's-pop',     name: 'Pop',     color: '#ec4899' },
  { id: 's-festa',   name: 'Festa',   color: '#f59e0b' },
  { id: 's-relax',   name: 'Relax',   color: '#10b981' },
  { id: 's-classic', name: 'Classic', color: '#8b5cf6' },
];

/* --- State (in-memory only; serialized into URL for sharing) --- */
const state = {
  songs: {},            // id -> { id, title, artist, cover, style }
  tiers: Object.fromEntries(TIERS.map(t => [t.id, []])),  // tier -> [songId]
  pool: [],             // [songId]
  styles: DEFAULT_STYLES.slice(),
  filter: null,         // styleId | null
  playlist: null,       // { id, name, owner, tracks }
};

let accessToken = null;
let tokenExpiresAt = 0;
let clientId = null;

/* ---------------- Utilities ---------------- */
function $(sel, root = document) { return root.querySelector(sel); }
function $$(sel, root = document) { return [...root.querySelectorAll(sel)]; }
function uid(prefix = 'id') { return prefix + '-' + Math.random().toString(36).slice(2, 10); }
function toast(msg, ms) {
  if (ms == null) ms = 2200;
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, ms);
}
function getRedirectUri() {
  const u = new URL(window.location.href);
  u.hash = '';
  u.search = '';
  return u.toString();
}

/* ---------------- PKCE helpers ---------------- */
function randomString(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map(b => ('0' + b.toString(16)).slice(-2)).join('').slice(0, len);
}
async function sha256(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function startSpotifyAuth() {
  if (!clientId) {
    toast('Configure o Client ID primeiro');
    $('#setup').hidden = false;
    $('#clientId').focus();
    return;
  }
  const verifier = randomString(96);
  const challenge = await sha256(verifier);

  // We cannot use storage APIs in the sandboxed iframe. Instead, encode the
  // PKCE verifier + client ID into the OAuth `state` param, which Spotify
  // echoes back verbatim in the redirect. The state is not security-sensitive
  // in this flow because PKCE already binds the code to the verifier.
  const stateObj = { v: verifier, c: clientId, n: randomString(16) };
  const statePacked = btoa(unescape(encodeURIComponent(JSON.stringify(stateObj))));

  const scope = 'playlist-read-private playlist-read-collaborative';
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: getRedirectUri(),
    code_challenge_method: 'S256',
    code_challenge: challenge,
    state: statePacked,
    scope,
  });
  window.location.href = 'https://accounts.spotify.com/authorize?' + params.toString();
}

async function exchangeCodeForToken(code, statePacked) {
  let verifier, savedClient;
  try {
    const unpacked = JSON.parse(decodeURIComponent(escape(atob(statePacked))));
    verifier = unpacked.v;
    savedClient = unpacked.c;
  } catch {
    throw new Error('State OAuth inválido');
  }
  if (!verifier || !savedClient) throw new Error('PKCE state ausente');
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: getRedirectUri(),
    client_id: savedClient,
    code_verifier: verifier,
  });
  const res = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) throw new Error('Falha no token: ' + res.status);
  const data = await res.json();
  accessToken = data.access_token;
  tokenExpiresAt = Date.now() + (data.expires_in * 1000);
  clientId = savedClient; // ensure clientId is set for subsequent calls
}



/* ---------------- Spotify API ---------------- */
async function spotifyFetch(path, opts = {}) {
  const url = path.startsWith('http') ? path : 'https://api.spotify.com/v1' + path;
  const res = await fetch(url, {
    ...opts,
    headers: { Authorization: 'Bearer ' + accessToken, ...(opts.headers || {}) },
  });
  if (res.status === 401) {
    accessToken = null;
    tokenExpiresAt = 0;
    updateAuthButton();
    throw new Error('Sessão Spotify expirou — entre novamente');
  }
  if (res.status === 403) {
    const err = new Error('403');
    err.status = 403;
    throw err;
  }
  if (res.status === 404) {
    throw new Error('Playlist não encontrada (verifique se o link está correto e se a playlist é pública)');
  }
  if (!res.ok) throw new Error('Spotify API erro ' + res.status);
  return res.json();
}

function extractPlaylistId(input) {
  if (!input) return null;
  input = input.trim();
  // URL
  const m = input.match(/playlist[/:]([a-zA-Z0-9]+)/);
  if (m) return m[1];
  // Plain ID
  if (/^[a-zA-Z0-9]{10,}$/.test(input)) return input;
  return null;
}

async function loadPlaylist(playlistId) {
  if (!accessToken) {
    toast('Entre com o Spotify primeiro');
    return;
  }
  // Editorial/algorithmic playlists (37i9dQZ...) are blocked in dev mode since Nov 2024
  if (playlistId.startsWith('37i9dQZ')) {
    toast('Playlists editoriais do Spotify (Top Hits, RapCaviar, etc.) não funcionam em Development Mode. Use uma playlist criada por usuário.', 6000);
    return;
  }
  try {
    toast('Carregando playlist…');
    const meta = await spotifyFetch(`/playlists/${playlistId}?fields=id,name,owner(display_name),images`);
    const tracks = [];
    // Use /items (new endpoint) instead of deprecated /tracks
    let url = `/playlists/${playlistId}/items?limit=100&fields=items(track(id,name,artists(name),album(images,name))),next`;
    while (url) {
      const page = await spotifyFetch(url);
      for (const it of page.items || []) {
        const t = it.track;
        if (!t || !t.id) continue;
        tracks.push({
          id: t.id,
          title: t.name,
          artist: (t.artists || []).map(a => a.name).join(', '),
          cover: (t.album && t.album.images && t.album.images[0] && t.album.images[0].url) || null,
          style: null,
        });
      }
      url = page.next || null;
    }
    // Reset state for new playlist
    state.playlist = {
      id: meta.id,
      name: meta.name,
      owner: meta.owner && meta.owner.display_name,
      cover: (meta.images && meta.images[0] && meta.images[0].url) || null,
      count: tracks.length,
    };
    state.songs = {};
    for (const t of tracks) state.songs[t.id] = t;
    state.tiers = Object.fromEntries(TIERS.map(t => [t.id, []]));
    state.pool = tracks.map(t => t.id);
    state.filter = null;
    updatePlaylistMeta();
    renderAll();
    toast(`${tracks.length} músicas carregadas`);
  } catch (e) {
    console.error(e);
    if (e.status === 403) {
      toast('403 — Acesso negado. Possíveis causas: (1) playlist editorial/algorítmica do Spotify (não funciona em Dev Mode), (2) sua conta não está na allowlist do app. Tente com uma playlist sua.', 8000);
    } else {
      toast(e.message || 'Erro ao carregar playlist');
    }
  }
}

/* ---------------- Demo data ---------------- */
function loadDemo() {
  const demo = [
    ['demo-1', 'Smells Like Teen Spirit', 'Nirvana', 's-grunge'],
    ['demo-2', 'Black Hole Sun', 'Soundgarden', 's-grunge'],
    ['demo-3', 'Bohemian Rhapsody', 'Queen', 's-classic'],
    ['demo-4', 'Billie Jean', 'Michael Jackson', 's-pop'],
    ['demo-5', 'Sweet Child O\' Mine', 'Guns N\' Roses', 's-rock'],
    ['demo-6', 'Blinding Lights', 'The Weeknd', 's-pop'],
    ['demo-7', 'Clair de Lune', 'Debussy', 's-classic'],
    ['demo-8', 'One Dance', 'Drake', 's-festa'],
    ['demo-9', 'Weightless', 'Marconi Union', 's-relax'],
    ['demo-10', 'Wonderwall', 'Oasis', 's-rock'],
    ['demo-11', 'Levitating', 'Dua Lipa', 's-festa'],
    ['demo-12', 'Hotel California', 'Eagles', 's-rock'],
  ];
  state.songs = {};
  state.tiers = Object.fromEntries(TIERS.map(t => [t.id, []]));
  state.pool = [];
  for (const [id, title, artist, style] of demo) {
    state.songs[id] = { id, title, artist, cover: null, style };
    state.pool.push(id);
  }
  state.filter = null;
  state.playlist = { id: 'demo', name: 'Playlist de Exemplo', owner: 'Demo', cover: null, count: demo.length };
  updatePlaylistMeta();
  renderAll();
  toast('Modo demo carregado');
}

/* ---------------- Rendering ---------------- */
function renderAll() {
  renderStyleChips();
  renderTierBoard();
  renderPool();
}

function renderStyleChips() {
  const root = $('#filterStyles');
  root.innerHTML = '';
  const all = document.createElement('button');
  all.className = 'style-chip' + (state.filter === null ? ' active' : '');
  all.innerHTML = `<span class="dot"></span>Todos`;
  all.onclick = () => { state.filter = null; renderAll(); };
  root.appendChild(all);
  for (const s of state.styles) {
    const chip = document.createElement('button');
    chip.className = 'style-chip' + (state.filter === s.id ? ' active' : '');
    chip.style.setProperty('--chip-color', s.color);
    chip.innerHTML = `<span class="dot"></span>${s.name}`;
    chip.onclick = () => { state.filter = state.filter === s.id ? null : s.id; renderAll(); };
    root.appendChild(chip);
  }
}

function renderTierBoard() {
  const board = $('#tierBoard');
  board.innerHTML = '';
  for (const t of TIERS) {
    const row = document.createElement('div');
    row.className = 'tier-row';
    row.style.setProperty('--tier-color', t.color);

    const label = document.createElement('div');
    label.className = 'tier-label';
    label.textContent = t.id;
    row.appendChild(label);

    const drop = document.createElement('div');
    drop.className = 'tier-drop';
    drop.dataset.tier = t.id;
    drop.dataset.testid = 'tier-' + t.id;

    for (const songId of state.tiers[t.id]) {
      const song = state.songs[songId];
      if (!song) continue;
      if (state.filter && song.style !== state.filter) continue;
      drop.appendChild(renderSongCard(song));
    }
    row.appendChild(drop);
    board.appendChild(row);

    makeSortable(drop, t.id);
  }
}

function renderPool() {
  const pool = $('#pool');
  pool.innerHTML = '';
  const visible = state.pool.filter(id => {
    const s = state.songs[id];
    return s && (!state.filter || s.style === state.filter);
  });

  const total = Object.keys(state.songs).length;
  $('#poolCount').textContent = state.filter
    ? `${visible.length} visíveis · ${state.pool.length} / ${total} no pool`
    : `${state.pool.length} / ${total}`;

  if (state.pool.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.innerHTML = `
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>
      <p>Entre com o Spotify e cole o link de uma playlist para começar.</p>
      <button class="btn-ghost" id="btnLoadDemo">Ou experimente com dados de exemplo</button>
    `;
    pool.appendChild(empty);
    $('#btnLoadDemo').onclick = loadDemo;
  } else {
    for (const id of visible) {
      pool.appendChild(renderSongCard(state.songs[id]));
    }
  }
  makeSortable(pool, '__pool__');
}

function renderSongCard(song) {
  const el = document.createElement('div');
  el.className = 'song';
  el.dataset.songId = song.id;
  el.dataset.testid = 'song-' + song.id;

  // Cover
  if (song.cover) {
    const img = document.createElement('img');
    img.src = song.cover;
    img.alt = song.title;
    img.loading = 'lazy';
    img.crossOrigin = 'anonymous';
    img.referrerPolicy = 'no-referrer';
    el.appendChild(img);
  } else {
    const ph = document.createElement('div');
    ph.className = 'placeholder';
    ph.innerHTML = `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>`;
    el.appendChild(ph);
  }

  // Style indicator
  if (song.style) {
    const styleObj = state.styles.find(s => s.id === song.style);
    if (styleObj) {
      const dot = document.createElement('span');
      dot.className = 'style-indicator';
      dot.style.setProperty('--chip-color', styleObj.color);
      el.appendChild(dot);
    }
  }

  // Tooltip
  const tip = document.createElement('div');
  tip.className = 'tooltip';
  tip.innerHTML = `<div class="title">${escapeHtml(song.title)}</div><div class="artist">${escapeHtml(song.artist)}</div>`;
  el.appendChild(tip);

  // Menu button
  const menuBtn = document.createElement('button');
  menuBtn.className = 'song-menu-btn';
  menuBtn.textContent = '⋯';
  menuBtn.setAttribute('aria-label', 'Opções');
  menuBtn.onclick = (ev) => {
    ev.stopPropagation();
    openSongPopover(song, el);
  };
  el.appendChild(menuBtn);

  return el;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ---------------- Song popover ---------------- */
let activePopover = null;
function openSongPopover(song, anchor) {
  if (activePopover) { activePopover.remove(); activePopover = null; }
  const pop = document.createElement('div');
  pop.className = 'song-popover';
  pop.innerHTML = `
    <div class="sec-label">Estilo</div>
    <select id="popStyle">
      <option value="">— sem estilo —</option>
      ${state.styles.map(s => `<option value="${s.id}" ${song.style === s.id ? 'selected' : ''}>${escapeHtml(s.name)}</option>`).join('')}
    </select>
    <div style="height:6px"></div>
    <button class="danger" id="popRemove">Remover música</button>
  `;
  document.body.appendChild(pop);
  const rect = anchor.getBoundingClientRect();
  const top = rect.bottom + window.scrollY + 4;
  let left = rect.left + window.scrollX;
  const popWidth = 200;
  if (left + popWidth > window.innerWidth - 8) left = window.innerWidth - popWidth - 8;
  pop.style.top = top + 'px';
  pop.style.left = left + 'px';
  activePopover = pop;

  $('#popStyle', pop).onchange = (e) => {
    song.style = e.target.value || null;
    renderAll();
    pop.remove(); activePopover = null;
  };
  $('#popRemove', pop).onclick = () => {
    delete state.songs[song.id];
    for (const tier of Object.values(state.tiers)) {
      const i = tier.indexOf(song.id);
      if (i >= 0) tier.splice(i, 1);
    }
    const i = state.pool.indexOf(song.id);
    if (i >= 0) state.pool.splice(i, 1);
    renderAll();
    pop.remove(); activePopover = null;
  };

  setTimeout(() => {
    document.addEventListener('click', closePop, { once: true });
  }, 0);
  function closePop(ev) {
    if (!pop.contains(ev.target)) { pop.remove(); activePopover = null; }
    else { document.addEventListener('click', closePop, { once: true }); }
  }
}

/* ---------------- Drag & drop ---------------- */
function makeSortable(el, tierId) {
  if (el._sortable) el._sortable.destroy();
  el._sortable = Sortable.create(el, {
    group: 'songs',
    animation: 180,
    ghostClass: 'sortable-ghost',
    chosenClass: 'sortable-chosen',
    filter: '.song-menu-btn',
    preventOnFilter: false,
    onEnd: () => syncFromDom(),
  });
}

function syncFromDom() {
  // Rebuild tiers and pool from current DOM order
  const newTiers = Object.fromEntries(TIERS.map(t => [t.id, []]));
  for (const t of TIERS) {
    const el = document.querySelector(`.tier-drop[data-tier="${t.id}"]`);
    if (!el) continue;
    for (const card of $$('.song', el)) {
      newTiers[t.id].push(card.dataset.songId);
    }
  }
  const poolEl = $('#pool');
  const poolCurrent = $$('.song', poolEl).map(c => c.dataset.songId);

  // Preserve songs currently filtered out (not visible in DOM)
  // by keeping them in their previous containers
  const visibleIds = new Set([
    ...poolCurrent,
    ...Object.values(newTiers).flat(),
  ]);
  const hiddenFromTiers = {};
  const hiddenPool = [];
  for (const t of TIERS) {
    hiddenFromTiers[t.id] = state.tiers[t.id].filter(id => !visibleIds.has(id));
  }
  for (const id of state.pool) if (!visibleIds.has(id)) hiddenPool.push(id);

  state.tiers = Object.fromEntries(TIERS.map(t => [t.id, [...hiddenFromTiers[t.id], ...newTiers[t.id]]]));
  state.pool = [...hiddenPool, ...poolCurrent];
  updateCounts();
}

function updateCounts() {
  const total = Object.keys(state.songs).length;
  const unranked = state.pool.length;
  $('#poolCount').textContent = `${unranked} / ${total}`;
}

/* ---------------- Playlist meta ---------------- */
function updatePlaylistMeta() {
  const meta = $('#playlistMeta');
  if (!state.playlist) { meta.hidden = true; return; }
  meta.hidden = false;
  const img = $('#playlistCover');
  if (state.playlist.cover) { img.src = state.playlist.cover; img.style.display = 'block'; }
  else img.style.display = 'none';
  $('#playlistName').textContent = state.playlist.name;
  $('#playlistSub').textContent = `${state.playlist.count} músicas · ${state.playlist.owner || ''}`;
}

/* ---------------- Styles modal ---------------- */
function openStylesModal() {
  const list = $('#stylesList');
  list.innerHTML = '';
  for (const s of state.styles) {
    const row = document.createElement('div');
    row.className = 'style-row';
    row.innerHTML = `
      <input type="color" value="${s.color}" />
      <input type="text" value="${escapeHtml(s.name)}" maxlength="24" />
      <button class="btn-icon" aria-label="Remover">✕</button>
    `;
    const [color, name, del] = row.children;
    color.oninput = (e) => { s.color = e.target.value; };
    name.oninput = (e) => { s.name = e.target.value; };
    del.onclick = () => {
      state.styles = state.styles.filter(x => x.id !== s.id);
      // Clear style from songs that used it
      for (const sg of Object.values(state.songs)) if (sg.style === s.id) sg.style = null;
      if (state.filter === s.id) state.filter = null;
      openStylesModal();
    };
    list.appendChild(row);
  }
  $('#stylesModal').hidden = false;
}
function closeStylesModal() {
  $('#stylesModal').hidden = true;
  renderAll();
}

/* ---------------- Share & export ---------------- */
function serializeState() {
  const compact = {
    s: state.styles.map(x => [x.id, x.name, x.color]),
    t: Object.fromEntries(TIERS.map(t => [t.id, state.tiers[t.id]])),
    p: state.pool,
    m: Object.values(state.songs).map(s => [s.id, s.title, s.artist, s.cover || '', s.style || '']),
    pl: state.playlist ? [state.playlist.id, state.playlist.name, state.playlist.owner || '', state.playlist.cover || ''] : null,
  };
  const json = JSON.stringify(compact);
  return btoa(unescape(encodeURIComponent(json))); // base64
}

function deserializeState(b64) {
  try {
    const json = decodeURIComponent(escape(atob(b64)));
    const c = JSON.parse(json);
    state.styles = c.s.map(([id, name, color]) => ({ id, name, color }));
    state.tiers = Object.fromEntries(TIERS.map(t => [t.id, c.t[t.id] || []]));
    state.pool = c.p || [];
    state.songs = {};
    for (const [id, title, artist, cover, style] of c.m || []) {
      state.songs[id] = { id, title, artist, cover: cover || null, style: style || null };
    }
    if (c.pl) {
      state.playlist = { id: c.pl[0], name: c.pl[1], owner: c.pl[2], cover: c.pl[3], count: (c.m || []).length };
    }
    updatePlaylistMeta();
    renderAll();
    return true;
  } catch (e) {
    console.error('Bad share URL', e);
    return false;
  }
}

async function shareTierList() {
  const b64 = serializeState();
  const url = new URL(window.location.href);
  url.hash = 'share=' + b64;
  try {
    await navigator.clipboard.writeText(url.toString());
    toast('Link copiado — compartilhe com quem quiser');
  } catch {
    window.prompt('Copie o link:', url.toString());
  }
}

async function exportPng() {
  toast('Gerando imagem…');
  // Hide empty state and tooltips during capture
  const board = $('#tierBoard');
  const clone = board.cloneNode(true);
  // Build a capture container with title + board
  const cap = document.createElement('div');
  cap.style.position = 'fixed';
  cap.style.left = '-99999px';
  cap.style.top = '0';
  cap.style.padding = '32px';
  cap.style.background = getComputedStyle(document.body).backgroundColor;
  cap.style.width = board.offsetWidth + 'px';

  const title = document.createElement('div');
  title.style.fontFamily = getComputedStyle(document.body).fontFamily;
  title.style.fontSize = '24px';
  title.style.fontWeight = '700';
  title.style.color = getComputedStyle(document.body).color;
  title.style.marginBottom = '16px';
  title.textContent = state.playlist ? `Tier List · ${state.playlist.name}` : 'Music Tier List';
  cap.appendChild(title);
  cap.appendChild(clone);
  document.body.appendChild(cap);

  try {
    const canvas = await html2canvas(cap, {
      backgroundColor: getComputedStyle(document.body).backgroundColor,
      scale: 2,
      useCORS: true,
      allowTaint: true,
      logging: false,
    });
    const link = document.createElement('a');
    const safe = (state.playlist?.name || 'tier-list').replace(/[^\w]+/g, '-').toLowerCase();
    link.download = `${safe}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
    toast('Imagem exportada');
  } catch (e) {
    console.error(e);
    toast('Erro ao exportar imagem');
  } finally {
    cap.remove();
  }
}

/* ---------------- Theme ---------------- */
(function initTheme() {
  const root = document.documentElement;
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  let theme = prefersDark ? 'dark' : 'dark'; // default to dark regardless; Spotify-feel
  root.setAttribute('data-theme', theme);
  const btn = $('#btnTheme');
  function updateIcon() {
    btn.innerHTML = theme === 'dark'
      ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
      : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  }
  updateIcon();
  btn.onclick = () => {
    theme = theme === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', theme);
    updateIcon();
  };
})();

/* ---------------- Event wiring ---------------- */
async function init() {
  // Redirect URI display
  $('#redirectUri').value = getRedirectUri();
  $('#btnCopyRedirect').onclick = async () => {
    try { await navigator.clipboard.writeText(getRedirectUri()); toast('Copiado'); }
    catch { $('#redirectUri').select(); document.execCommand('copy'); toast('Copiado'); }
  };

  // Client ID: in-memory only. User re-enters each session (no storage allowed).
  if (clientId) $('#clientId').value = clientId;
  $('#btnSaveClient').onclick = () => {
    const v = $('#clientId').value.trim();
    if (!v) return toast('Cole o Client ID');
    clientId = v;
    toast('Client ID salvo');
    $('#setup').hidden = true;
  };

  // Handle OAuth callback (?code=…&state=…). The state carries the PKCE
  // verifier + client ID since we can't use sessionStorage in the sandbox.
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has('code') && urlParams.has('state')) {
    try {
      await exchangeCodeForToken(urlParams.get('code'), urlParams.get('state'));
      // Clean URL
      const clean = getRedirectUri() + (window.location.hash || '');
      window.history.replaceState({}, '', clean);
      updateAuthButton();
      toast('Conectado ao Spotify');
    } catch (e) {
      console.error(e);
      toast('Falha na autenticação: ' + e.message);
    }
  }

  updateAuthButton();

  // Show setup if no client id
  if (!clientId) $('#setup').hidden = false;

  // Buttons
  $('#btnAuth').onclick = () => {
    if (accessToken) {
      accessToken = null;
      tokenExpiresAt = 0;
      updateAuthButton();
      toast('Sessão encerrada');
    } else {
      startSpotifyAuth();
    }
  };
  $('#btnLoadPlaylist').onclick = () => {
    const id = extractPlaylistId($('#playlistUrl').value);
    if (!id) return toast('Cole um link/ID de playlist válido');
    loadPlaylist(id);
  };
  $('#playlistUrl').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('#btnLoadPlaylist').click();
  });

  $('#btnShare').onclick = shareTierList;
  $('#btnExport').onclick = exportPng;
  $('#btnReset').onclick = () => {
    if (!confirm('Mover todas as músicas de volta para o pool?')) return;
    const all = [...Object.values(state.tiers).flat(), ...state.pool];
    state.tiers = Object.fromEntries(TIERS.map(t => [t.id, []]));
    state.pool = all;
    renderAll();
  };

  // Styles modal
  $('#btnEditStyles').onclick = openStylesModal;
  $('#btnAddStyle').onclick = () => {
    const palette = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316'];
    const c = palette[state.styles.length % palette.length];
    state.styles.push({ id: uid('s'), name: 'Novo estilo', color: c });
    openStylesModal();
  };
  document.addEventListener('click', (e) => {
    if (e.target.matches('[data-close-modal]')) closeStylesModal();
  });

  // Demo button (delegated because re-rendered)
  document.addEventListener('click', (e) => {
    if (e.target.id === 'btnLoadDemo') loadDemo();
  });

  // Shared state via URL hash
  if (window.location.hash.startsWith('#share=')) {
    const b64 = window.location.hash.slice('#share='.length);
    if (deserializeState(b64)) toast('Tier list compartilhada carregada');
  } else {
    renderAll();
  }
}

function updateAuthButton() {
  const btn = $('#btnAuth');
  const label = $('#btnAuthLabel');
  if (accessToken) {
    btn.classList.add('authenticated');
    label.textContent = 'Conectado · Sair';
  } else {
    btn.classList.remove('authenticated');
    label.textContent = 'Entrar com Spotify';
  }
}

init();
