'use strict';

// Empty string = relative URLs, so the app works on any host/port without changes.
// All fetch calls like fetch(`${BASE_URL}/login`) become fetch('/login').
const BASE_URL = '';

// ============================================================
// STORAGE HELPERS
// ============================================================

function getUserId() {
  return localStorage.getItem('user_id');
}

function setUserId(id) {
  localStorage.setItem('user_id', String(id));
}

// ============================================================
// PAGE ROUTING
// ============================================================

const PAGE_IDS = ['login-page', 'create-account-page', 'dashboard-page'];

function showPage(pageId) {
  PAGE_IDS.forEach(id => {
    document.getElementById(id).classList.toggle('hidden', id !== pageId);
  });
}

function requireAuth() {
  if (!getUserId()) {
    showPage('login-page');
    return false;
  }
  return true;
}

// ============================================================
// UTILITIES
// ============================================================

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideError(el) {
  el.textContent = '';
  el.classList.add('hidden');
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ============================================================
// FETCH-BASED AUTH REQUEST
// Used for login and create_user. The backend returns 200 JSON for
// all outcomes, including OAuth redirects — it sends
// {"redirect_url": "/google_auth?user_id=X"} instead of a 303 so
// that the Fetch API never sees a redirect and we can read the body.
// ============================================================

function makeAuthRequest(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then(response =>
    response.json().then(data => ({ status: response.status, data }))
  );
}

// ============================================================
// LOGIN PAGE
// ============================================================

function initLoginPage() {
  document.getElementById('go-to-create').addEventListener('click', (e) => {
    e.preventDefault();
    showPage('create-account-page');
  });

  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errorEl = document.getElementById('login-error');
    hideError(errorEl);

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
      showError(errorEl, 'Please enter your username and password.');
      return;
    }

    const btn = e.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    let result;
    try {
      result = await makeAuthRequest(`${BASE_URL}/login`, { username, password });
    } catch {
      btn.disabled = false;
      btn.textContent = 'Login';
      showError(errorEl, 'Could not connect to the server. Is the backend running?');
      return;
    }

    btn.disabled = false;
    btn.textContent = 'Login';

    if (result.status >= 400) {
      showError(errorEl, result.data.detail || 'Login failed. Please try again.');
    } else if (result.data.redirect_url) {
      const dest = result.data.redirect_url.startsWith('http')
        ? result.data.redirect_url
        : `https://connect-to-the-music.onrender.com${result.data.redirect_url}`;
      window.location.href = dest;
    } else if (result.data.user_id) {
      setUserId(result.data.user_id);
      showPage('dashboard-page');
      loadPlaylists();
    }
  });
}

// ============================================================
// CREATE ACCOUNT PAGE
// ============================================================

function initCreateAccountPage() {
  document.getElementById('go-to-login').addEventListener('click', (e) => {
    e.preventDefault();
    showPage('login-page');
  });

  document.getElementById('create-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errorEl = document.getElementById('create-error');
    hideError(errorEl);

    const username = document.getElementById('create-username').value.trim();
    const password = document.getElementById('create-password').value;

    if (!username || !password) {
      showError(errorEl, 'Please enter a username and password.');
      return;
    }
    if (username.length < 2) {
      showError(errorEl, 'Username must be at least 2 characters.');
      return;
    }

    const btn = e.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Creating account...';

    let result;
    try {
      result = await makeAuthRequest(`${BASE_URL}/create_user`, { username, password });
    } catch {
      btn.disabled = false;
      btn.textContent = 'Verify';
      showError(errorEl, 'Could not connect to the server. Is the backend running?');
      return;
    }

    btn.disabled = false;
    btn.textContent = 'Verify';

    if (result.status >= 400) {
      showError(errorEl, result.data.detail || 'Account creation failed. Please try again.');
    } else if (result.data.redirect_url) {
      const dest = result.data.redirect_url.startsWith('http')
        ? result.data.redirect_url
        : `http://127.0.0.1:8000${result.data.redirect_url}`;
      window.location.href = dest;
    } else if (result.data.user_id) {
      setUserId(result.data.user_id);
      showPage('dashboard-page');
      loadPlaylists();
    }
  });
}

// ============================================================
// DASHBOARD — PLAYLIST LOADING
// ============================================================

async function loadPlaylists() {
  if (!requireAuth()) return;

  const grid = document.getElementById('playlist-grid');
  grid.innerHTML = '<div class="loading-state">Loading your playlists...</div>';

  try {
    const res = await fetch(`${BASE_URL}/playlists/${getUserId()}`);
    const data = await res.json();

    if (!res.ok) {
      grid.innerHTML = `<div class="error-center">${escapeHtml(data.detail || 'Failed to load playlists.')}</div>`;
      return;
    }

    renderPlaylists(data.playlists || []);
  } catch {
    grid.innerHTML = '<div class="error-center">Could not connect to the server. Is the backend running?</div>';
  }
}

function getPlatformIcon(platform) {
  if (platform === 'youtube') {
    return `
      <div class="platform-icon">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 90 63" width="60" height="42" aria-label="YouTube">
          <rect width="90" height="63" rx="14" fill="#FF0000"/>
          <polygon points="35,13 35,50 63,31.5" fill="#FFFFFF"/>
        </svg>
      </div>`;
  }

  if (platform === 'spotify') {
    return `
      <div class="platform-icon">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="50" height="50" aria-label="Spotify">
          <circle cx="50" cy="50" r="50" fill="#1DB954"/>
          <path d="M24,64 Q50,52 76,64" stroke="#FFFFFF" stroke-width="7" stroke-linecap="round" fill="none"/>
          <path d="M20,50 Q50,36 80,50" stroke="#FFFFFF" stroke-width="7" stroke-linecap="round" fill="none"/>
          <path d="M16,36 Q50,20 84,36" stroke="#FFFFFF" stroke-width="7" stroke-linecap="round" fill="none"/>
        </svg>
      </div>`;
  }

  // 'both' or anything else
  return '<div class="platform-icon emoji-icon">🎵</div>';
}

function renderPlaylists(playlists) {
  const grid = document.getElementById('playlist-grid');

  if (!playlists.length) {
    grid.innerHTML = '<div class="empty-state">No playlists yet — create one to get started!</div>';
    return;
  }

  grid.innerHTML = playlists.map(pl => `
    <div class="playlist-card">
      ${getPlatformIcon(pl.platform)}
      <div class="playlist-name">${escapeHtml(pl.name)}</div>
      <div class="playlist-date">${formatDate(pl.created_at)}</div>
    </div>
  `).join('');
}

// ============================================================
// MODALS — OPEN / CLOSE
// ============================================================

function openModal(modalId) {
  document.getElementById(modalId).classList.remove('hidden');
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  modal.classList.add('hidden');

  // Reset all text inputs and checkboxes inside the modal.
  modal.querySelectorAll('input[type="text"], input[type="password"]').forEach(el => {
    el.value = '';
  });
  modal.querySelectorAll('input[type="checkbox"]').forEach(el => {
    el.checked = false;
  });

  // Hide any visible error messages.
  modal.querySelectorAll('.modal-error').forEach(el => {
    el.textContent = '';
    el.classList.add('hidden');
  });
}

function setModalError(modalId, msg) {
  const errEl = document.querySelector(`#${modalId} .modal-error`);
  if (errEl) {
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
  }
}

function clearModalError(modalId) {
  const errEl = document.querySelector(`#${modalId} .modal-error`);
  if (errEl) {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }
}

// Runs an async API call for a modal action.
// On success: closes the modal and refreshes playlists.
// On error: shows the detail message inside the modal.
async function executeModalAction(modalId, apiFn) {
  const btn = document.querySelector(`#${modalId} .modal-action-btn`);
  const originalText = btn.textContent;

  clearModalError(modalId);
  btn.disabled = true;
  btn.textContent = 'Processing...';

  try {
    const res = await apiFn();
    if (res.ok) {
      closeModal(modalId);
      loadPlaylists();
    } else {
      const data = await res.json();
      setModalError(modalId, data.detail || 'An error occurred. Please try again.');
    }
  } catch (err) {
    setModalError(modalId, err.message || 'Failed to connect to the server.');
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

// ============================================================
// MODALS — WIRING
// ============================================================

function initModals() {
  // --- Global: close on overlay click or X button ---
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    // Close when clicking the dark backdrop (not the card itself).
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.classList.add('hidden');
        // Clear errors and inputs when dismissed.
        closeModal(overlay.id);
      }
    });

    overlay.querySelector('.modal-close').addEventListener('click', () => {
      closeModal(overlay.id);
    });
  });

  // --- CREATE PLAYLIST ---
  document.getElementById('btn-create-playlist').addEventListener('click', () => {
    openModal('modal-create');
  });

  document.querySelector('#modal-create .modal-action-btn').addEventListener('click', () => {
    const name     = document.getElementById('cp-name').value.trim();
    const platform = document.getElementById('cp-platform').value;
    const userId   = parseInt(getUserId(), 10);

    if (!name) {
      setModalError('modal-create', 'Please enter a playlist name.');
      return;
    }

    executeModalAction('modal-create', () =>
      fetch(`${BASE_URL}/create_playlist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, user_id: userId, platform }),
      })
    );
  });

  // --- ADD PLAYLIST ---
  document.getElementById('btn-add-playlist').addEventListener('click', () => {
    openModal('modal-add');
  });

  document.querySelector('#modal-add .modal-action-btn').addEventListener('click', () => {
    const name     = document.getElementById('ap-name').value.trim();
    const platform = document.getElementById('ap-platform').value;
    const userId   = parseInt(getUserId(), 10);

    if (!name) {
      setModalError('modal-add', 'Please enter a playlist name.');
      return;
    }

    executeModalAction('modal-add', () =>
      fetch(`${BASE_URL}/add_playlist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, platform, user_id: userId }),
      })
    );
  });

  // --- COPY PLAYLIST ---
  document.getElementById('btn-copy-playlist').addEventListener('click', () => {
    openModal('modal-copy');
  });

  document.querySelector('#modal-copy .modal-action-btn').addEventListener('click', () => {
    const name     = document.getElementById('cop-name').value.trim();
    const platform = document.getElementById('cop-platform').value;
    const sync     = document.getElementById('cop-sync').checked;
    const userId   = parseInt(getUserId(), 10);

    if (!name) {
      setModalError('modal-copy', 'Please enter a playlist name.');
      return;
    }

    executeModalAction('modal-copy', () =>
      fetch(`${BASE_URL}/copy_playlist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, platform, user_id: userId, sync }),
      })
    );
  });

  // --- SYNC PLAYLIST ---
  document.getElementById('btn-sync-playlist').addEventListener('click', () => {
    openModal('modal-sync');
  });

  document.querySelector('#modal-sync .modal-action-btn').addEventListener('click', () => {
    const name     = document.getElementById('scp-name').value.trim();
    const platform = document.getElementById('scp-platform').value;
    const userId   = parseInt(getUserId(), 10);

    if (!name) {
      setModalError('modal-sync', 'Please enter a playlist name.');
      return;
    }

    executeModalAction('modal-sync', () =>
      fetch(`${BASE_URL}/sync_playlist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, user_id: userId, override_platform: platform }),
      })
    );
  });

  // --- DELETE PLAYLIST ---
  document.getElementById('btn-delete-playlist').addEventListener('click', () => {
    openModal('modal-delete');
  });

  document.querySelector('#modal-delete .modal-action-btn').addEventListener('click', () => {
    const name     = document.getElementById('dp-name').value.trim();
    const platform = document.getElementById('dp-platform').value;
    const userId   = getUserId();

    if (!name) {
      setModalError('modal-delete', 'Please enter a playlist name.');
      return;
    }

    const queryString = `name=${encodeURIComponent(name)}&platform=${encodeURIComponent(platform)}&user_id=${encodeURIComponent(userId)}`;

    executeModalAction('modal-delete', () =>
      fetch(`${BASE_URL}/delete_playlist?${queryString}`, {
        method: 'DELETE',
      })
    );
  });

  // --- LOGOUT ---
  document.getElementById('btn-logout').addEventListener('click', () => {
    openModal('modal-logout');
  });

  document.getElementById('btn-logout-cancel').addEventListener('click', () => {
    closeModal('modal-logout');
  });

  document.getElementById('btn-logout-confirm').addEventListener('click', async () => {
    const userId = parseInt(getUserId(), 10);
    try {
      const res = await fetch(`${BASE_URL}/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId }),
      });
      if (res.ok) {
        closeModal('modal-logout');
        localStorage.removeItem('user_id');
        showPage('login-page');
      } else {
        const data = await res.json();
        alert(`Error: ${data.detail || 'Could not log out.'}`);
      }
    } catch {
      alert('Failed to connect to the server. Please try again.');
    }
  });

  // --- DELETE ACCOUNT ---
  document.getElementById('btn-delete-account').addEventListener('click', () => {
    openModal('modal-delete-account');
  });

  document.getElementById('btn-delete-account-cancel').addEventListener('click', () => {
    closeModal('modal-delete-account');
  });

  document.getElementById('btn-delete-account-confirm').addEventListener('click', async () => {
    const userId = getUserId();
    try {
      const res = await fetch(`${BASE_URL}/delete_account?user_id=${encodeURIComponent(userId)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        closeModal('modal-delete-account');
        localStorage.clear();
        showPage('login-page');
      } else {
        const data = await res.json();
        alert(`Error: ${data.detail || 'Could not delete account.'}`);
      }
    } catch {
      alert('Failed to connect to the server. Please try again.');
    }
  });
}

// ============================================================
// DASHBOARD INITIALIZATION
// ============================================================

function initDashboard() {
  // The navbar buttons and modals are wired in initModals().
  // Playlist loading happens in loadPlaylists() called from showPage transitions.
}

// ============================================================
// APP INIT
// ============================================================

function init() {
  initLoginPage();
  initCreateAccountPage();
  initModals();
  initDashboard();

  // Check if the backend redirected back here after OAuth with a user_id param.
  // This happens after a successful Google + Spotify auth flow.
  const params = new URLSearchParams(window.location.search);
  const oauthUserId = params.get('user_id');
  if (oauthUserId) {
    setUserId(oauthUserId);
    // Remove the query param from the URL so it doesn't persist on refresh.
    window.history.replaceState({}, '', window.location.pathname);
    showPage('dashboard-page');
    loadPlaylists();
    return;
  }

  // Route to dashboard if already logged in, otherwise show login.
  const userId = getUserId();
  if (userId) {
    showPage('dashboard-page');
    loadPlaylists();
  } else {
    showPage('login-page');
  }
}

document.addEventListener('DOMContentLoaded', init);
