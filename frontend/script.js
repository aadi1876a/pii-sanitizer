// ══════════════════════════════════════════
//  CONFIG
// ══════════════════════════════════════════
const API = ''; // Works on localhost AND on Render automatically

// ══════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════
let currentRole  = 'user';
let fileType     = 'structured';
let fileCount    = 0;
let piiCount     = 0;
let fieldsCount  = 0;
let downloadCount = 0;
let userDownloadCount = 0;

// Users list (admin-managed)
const users = [
  { username: 'admin', role: 'admin',  addedOn: 'System' },
  { username: 'user',  role: 'user',   addedOn: 'System' },
];

// Date registry for filter dropdowns
const dateRegistry = {
  adminOriginalFiles:  new Set(),
  adminSanitizedFiles: new Set(),
  userSanitizedFiles:  new Set(),
};

// ══════════════════════════════════════════
//  ROLE & FILE TYPE TOGGLES
// ══════════════════════════════════════════
function setRole(role) {
  currentRole = role;
  document.getElementById('chipUser').classList.toggle('active', role === 'user');
  document.getElementById('chipAdmin').classList.toggle('active', role === 'admin');
  document.getElementById('adminKeyBox').classList.toggle('visible', role === 'admin');
}

function setFileType(type) {
  fileType = type;
  document.getElementById('typeStructured').classList.toggle('active', type === 'structured');
  document.getElementById('typeUnstructured').classList.toggle('active', type === 'unstructured');
}

// ══════════════════════════════════════════
//  ADMIN TABS
// ══════════════════════════════════════════
function showAdminTab(tab) {
  document.querySelectorAll('.admin-tab').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('adminTab-' + tab).style.display = 'block';
  const btns = document.querySelectorAll('.nav-btn');
  const labels = ['overview','files','users','audit'];
  btns[labels.indexOf(tab)].classList.add('active');
}

// ══════════════════════════════════════════
//  LOGIN
// ══════════════════════════════════════════
function login() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();

  if (currentRole === 'admin') {
    const key = document.getElementById('adminkey').value.trim();
    if (username === 'admin' && password === 'admin123' && key === 'ADMINKEY') {
      addAuditEntry('admin', 'LOGIN', 'Administrator session started', 'SUCCESS');
      showDashboard('adminDashboard');
    } else {
      shakeLogin();
      showToastError('Invalid administrator credentials');
    }
  } else {
    const found = users.find(u => u.username === username && u.role === 'user');
    const validPass = (username === 'user' && password === '1234') ||
                      (found && found.password === password);
    if (validPass || (username === 'user' && password === '1234')) {
      currentRole = 'user'; // ensure role is set correctly
      addAuditEntry(username, 'LOGIN', 'User session started', 'SUCCESS');
      showDashboard('userDashboard');
    } else {
      shakeLogin();
      showToastError('Invalid user credentials');
    }
  }
}

function showDashboard(id) {
  document.getElementById('loginCard').style.display = 'none';
  document.getElementById(id).style.display = 'block';
  showToast('Authentication successful');
}

function shakeLogin() {
  const card = document.getElementById('loginCard');
  card.style.animation = 'none';
  card.offsetHeight;
  card.style.animation = 'shake 0.4s ease';
}

function logout() {
  const who = currentRole === 'admin' ? 'admin' : 'user';
  addAuditEntry(who, 'LOGOUT', 'Session ended', 'SUCCESS');
  setTimeout(() => location.reload(), 300);
}

// ══════════════════════════════════════════
//  DOM READY
// ══════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('fileUpload').addEventListener('change', function () {
    const f = this.files[0];
    if (f) document.getElementById('fileNameDisplay').textContent = '→ ' + f.name;
  });

  const dropArea = document.getElementById('dropArea');
  dropArea.addEventListener('dragover',  e => { e.preventDefault(); dropArea.classList.add('dragover'); });
  dropArea.addEventListener('dragleave', ()  => dropArea.classList.remove('dragover'));
  dropArea.addEventListener('drop', e => {
    e.preventDefault(); dropArea.classList.remove('dragover');
    document.getElementById('fileUpload').files = e.dataTransfer.files;
    const f = e.dataTransfer.files[0];
    if (f) document.getElementById('fileNameDisplay').textContent = '→ ' + f.name;
  });

  // ── USER UPLOAD drop area (added) ──
  const userFileInput = document.getElementById('userFileUpload');
  const userDropArea  = document.getElementById('userDropArea');

  userFileInput.addEventListener('change', function () {
    const f = this.files[0];
    if (f) document.getElementById('userFileNameDisplay').textContent = '→ ' + f.name;
  });

  userDropArea.addEventListener('click', () => userFileInput.click());
  userDropArea.addEventListener('dragover',  e => { e.preventDefault(); userDropArea.classList.add('dragover'); });
  userDropArea.addEventListener('dragleave', ()  => userDropArea.classList.remove('dragover'));
  userDropArea.addEventListener('drop', e => {
    e.preventDefault(); userDropArea.classList.remove('dragover');
    userFileInput.files = e.dataTransfer.files;
    const f = e.dataTransfer.files[0];
    if (f) document.getElementById('userFileNameDisplay').textContent = '→ ' + f.name;
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && document.getElementById('loginCard').style.display !== 'none') login();
  });
});

// ══════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════
function formatSize(bytes) {
  if (bytes < 1024)        return bytes + ' B';
  if (bytes < 1048576)     return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function escHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function nowTimestamp() {
  return new Date().toLocaleString('en-US', { month:'short', day:'numeric', year:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit' });
}

function removeEmptyRow(tbodyId) {
  const el = document.querySelector('#' + tbodyId + ' .empty-row');
  if (el) el.remove();
}

function registerDate(tbodyId, dateStr) {
  if (!dateRegistry[tbodyId]) return;
  dateRegistry[tbodyId].add(dateStr);
  const selectMap = {
    adminOriginalFiles:  'adminOrigFilter',
    adminSanitizedFiles: 'adminSanFilter',
    userSanitizedFiles:  'userSanFilter',
  };
  const sel = document.getElementById(selectMap[tbodyId]);
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = '<option value="">All Dates</option>';
  [...dateRegistry[tbodyId]].sort().reverse().forEach(d => {
    const opt = document.createElement('option');
    opt.value = d; opt.textContent = d; sel.appendChild(opt);
  });
  sel.value = cur;
}

// ══════════════════════════════════════════
//  UPLOAD & SANITIZE  ← REAL BACKEND CALL
// ══════════════════════════════════════════
async function uploadFile() {
  const fileInput = document.getElementById('fileUpload');
  const file = fileInput.files[0];
  if (!file) { showToastError('Please select a file first'); return; }

  showToast('Uploading and sanitizing...');

  const formData = new FormData();
  formData.append('file', file);

  let data;
  try {
    const res = await fetch(`${API}/upload`, {
      method: 'POST',
      headers: { 'role': 'admin' },
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      showToastError(err.detail || 'Upload failed');
      addAuditEntry('admin', 'UPLOAD', `${file.name} - FAILED: ${err.detail}`, 'FAILED');
      return;
    }

    data = await res.json();

  } catch (e) {
    showToastError('Cannot connect to backend at localhost:8000');
    return;
  }

  const masked = data.pii_detected_count || 0;
  const fileId = data.file_id;
  const today  = new Date().toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' });

  fileCount++;
  piiCount    += masked;
  fieldsCount += masked;

  // Update admin stats
  document.getElementById('statTotal').textContent     = fileCount;
  document.getElementById('statPII').textContent       = piiCount;
  document.getElementById('statFields').textContent    = fieldsCount;
  document.getElementById('statSanitized').textContent = fileCount;

  // Update user stats if elements exist
  if (document.getElementById('userStatFiles'))
    document.getElementById('userStatFiles').textContent = fileCount;
  if (document.getElementById('userStatPII'))
    document.getElementById('userStatPII').textContent   = piiCount;

  const typeBadge = fileType === 'structured'
    ? '<span class="type-badge type-structured">Structured</span>'
    : '<span class="type-badge type-unstructured">Unstructured</span>';

  // ── ORIGINAL FILES ROW (admin only) ──
  removeEmptyRow('adminOriginalFiles');
  registerDate('adminOriginalFiles', today);
  const origRow = document.createElement('tr');
  origRow.dataset.name = file.name.toLowerCase();
  origRow.dataset.date = today;
  origRow.dataset.type = fileType;
  origRow.dataset.fileid = fileId;
  origRow.innerHTML = `
    <td>${escHtml(file.name)}</td>
    <td>${typeBadge}</td>
    <td><span class="size-tag">${formatSize(file.size)}</span></td>
    <td>${today}</td>
    <td style="display:flex;gap:6px;align-items:center;">
      <a href="#" onclick="downloadFile(event,'${fileId}',true)" class="btn-download">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="7 10 12 15 17 10"/>
          <line x1="12" y1="15" x2="12" y2="3"/>
        </svg> Download Original
      </a>
      <button class="btn-remove" onclick="deleteFile('${fileId}', this)">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="3 6 5 6 21 6"/>
          <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
          <path d="M10 11v6M14 11v6"/>
        </svg> Delete
      </button>
    </td>`;
  document.getElementById('adminOriginalFiles').prepend(origRow);

  // ── SANITIZED FILES ROW (admin + user) ──
  ['adminSanitizedFiles', 'userSanitizedFiles'].forEach(tbodyId => {
    removeEmptyRow(tbodyId);
    registerDate(tbodyId, today);
    const isUser = tbodyId === 'userSanitizedFiles';
    const sanRow = document.createElement('tr');
    sanRow.dataset.name = file.name.toLowerCase();
    sanRow.dataset.date = today;
    sanRow.dataset.type = fileType;
    sanRow.dataset.fileid = fileId;
    sanRow.innerHTML = `
      <td>${escHtml(file.name)}</td>
      <td>${typeBadge}</td>
      <td style="color:var(--cyan);">${masked} fields</td>
      <td style="color:var(--purple);">${masked} fields</td>
      <td>${today}</td>
      <td><span class="status-badge status-sanitized"><span class="status-dot-small"></span>Sanitized</span></td>
      <td style="display:flex;gap:6px;align-items:center;">
        <a href="#" onclick="downloadFile(event,'${fileId}',false)" class="btn-download">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg> Download
        </a>
        ${!isUser ? `<button class="btn-remove" onclick="deleteFile('${fileId}', this)">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
            <path d="M10 11v6M14 11v6"/>
          </svg> Delete
        </button>` : ''}
      </td>`;
    document.getElementById(tbodyId).prepend(sanRow);
  });

  addActivity(`<span>admin</span> uploaded and sanitized <span>${escHtml(file.name)}</span> — ${masked} PII fields masked`);
  addAuditEntry('admin', 'UPLOAD', `${file.name} (${fileType}, ${masked} PII masked)`, 'SUCCESS');

  document.getElementById('fileNameDisplay').textContent = '';
  fileInput.value = '';
  showToast(`✅ ${file.name} sanitized — ${masked} PII fields masked`);
}

// ══════════════════════════════════════════
//  USER FILE TYPE TOGGLE (added)
// ══════════════════════════════════════════
let userFileType = 'structured';

function setUserFileType(type) {
  userFileType = type;
  document.getElementById('userTypeStructured').classList.toggle('active', type === 'structured');
  document.getElementById('userTypeUnstructured').classList.toggle('active', type === 'unstructured');
}

// ══════════════════════════════════════════
//  USER UPLOAD & SANITIZE (added)
// ══════════════════════════════════════════
async function userUploadFile() {
  const fileInput = document.getElementById('userFileUpload');
  const file = fileInput.files[0];
  if (!file) { showToastError('Please select a file first'); return; }

  showToast('Uploading and sanitizing...');

  const formData = new FormData();
  formData.append('file', file);

  let data;
  try {
    const res = await fetch(`${API}/upload`, {
      method: 'POST',
      headers: { 'role': 'user' },
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      showToastError(err.detail || 'Upload failed');
      addAuditEntry('user', 'UPLOAD', `${file.name} - FAILED: ${err.detail}`, 'FAILED');
      return;
    }

    data = await res.json();

  } catch (e) {
    showToastError('Cannot connect to backend at localhost:8000');
    return;
  }

  const masked = data.pii_detected_count || 0;
  const fileId = data.file_id;
  const today  = new Date().toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' });

  fileCount++;
  piiCount    += masked;
  fieldsCount += masked;

  document.getElementById('statTotal').textContent     = fileCount;
  document.getElementById('statPII').textContent       = piiCount;
  document.getElementById('statFields').textContent    = fieldsCount;
  document.getElementById('statSanitized').textContent = fileCount;

  if (document.getElementById('userStatFiles'))
    document.getElementById('userStatFiles').textContent = fileCount;
  if (document.getElementById('userStatPII'))
    document.getElementById('userStatPII').textContent   = piiCount;

  const typeBadge = userFileType === 'structured'
    ? '<span class="type-badge type-structured">Structured</span>'
    : '<span class="type-badge type-unstructured">Unstructured</span>';

  ['adminSanitizedFiles', 'userSanitizedFiles'].forEach(tbodyId => {
    removeEmptyRow(tbodyId);
    registerDate(tbodyId, today);
    const sanRow = document.createElement('tr');
    sanRow.dataset.name = file.name.toLowerCase();
    sanRow.dataset.date = today;
    sanRow.dataset.type = userFileType;
    sanRow.dataset.fileid = fileId;
    sanRow.innerHTML = `
      <td>${escHtml(file.name)}</td>
      <td>${typeBadge}</td>
      <td style="color:var(--cyan);">${masked} fields</td>
      <td style="color:var(--purple);">${masked} fields</td>
      <td>${today}</td>
      <td><span class="status-badge status-sanitized"><span class="status-dot-small"></span>Sanitized</span></td>
      <td>
        <a href="#" onclick="downloadFile(event,'${fileId}',false)" class="btn-download">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg> Download
        </a>
      </td>`;
    document.getElementById(tbodyId).prepend(sanRow);
  });

  addAuditEntry('user', 'UPLOAD', `${file.name} (${userFileType}, ${masked} PII masked)`, 'SUCCESS');

  document.getElementById('userFileNameDisplay').textContent = '';
  fileInput.value = '';
  showToast(`✅ ${file.name} sanitized — ${masked} PII fields masked`);
}

// ══════════════════════════════════════════
//  DOWNLOAD FROM BACKEND
// ══════════════════════════════════════════
async function downloadFile(event, fileId, original = false) {
  event.preventDefault();
  try {
    const url = `${API}/download/${fileId}${original ? '?original=true' : ''}`;
    const res = await fetch(url, { headers: { 'role': currentRole } });
    if (!res.ok) { showToastError('Download failed'); return; }
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = res.headers.get('content-disposition')?.split('filename=')[1]?.replace(/"/g,'') || `file_${fileId}${original ? '_original' : '_sanitized'}`;
    a.click();
    countDownload(currentRole === 'admin' ? 'admin' : 'user');
    showToast('Download started!');
  } catch (e) {
    showToastError('Download failed — is backend running?');
  }
}

// ══════════════════════════════════════════
//  DELETE FILE (admin only)
// ══════════════════════════════════════════
async function deleteFile(fileId, btn) {
  if (!confirm('Are you sure you want to delete this file?')) return;
  try {
    const res = await fetch(`${API}/delete/${fileId}`, {
      method: 'DELETE',
      headers: { 'role': 'admin' }
    });
    if (!res.ok) { showToastError('Delete failed'); return; }

    // Remove ALL rows with this fileId across every table (original + sanitized admin + sanitized user)
    document.querySelectorAll(`tr[data-fileid="${fileId}"]`).forEach(row => row.remove());

    fileCount = Math.max(0, fileCount - 1);
    document.getElementById('statTotal').textContent     = fileCount;
    document.getElementById('statSanitized').textContent = fileCount;
    if (document.getElementById('userStatFiles'))
      document.getElementById('userStatFiles').textContent = fileCount;

    addAuditEntry('admin', 'DELETE', `File ${fileId} deleted`, 'SUCCESS');
    addActivity(`<span>admin</span> deleted file <span>${fileId}</span>`);
    showToast('File deleted successfully');
  } catch (e) {
    showToastError('Delete failed — is backend running?');
  }
}

// ══════════════════════════════════════════
//  DOWNLOAD COUNTER
// ══════════════════════════════════════════
function countDownload(who) {
  downloadCount++;
  document.getElementById('statDownloads').textContent = downloadCount;
  if (who === 'user') {
    userDownloadCount++;
    if (document.getElementById('userStatDownloads'))
      document.getElementById('userStatDownloads').textContent = userDownloadCount;
  }
  addAuditEntry(who, 'DOWNLOAD', 'PII-free file downloaded', 'SUCCESS');
}

// ══════════════════════════════════════════
//  USER MANAGEMENT
// ══════════════════════════════════════════
function addUser() {
  const uname = document.getElementById('newUsername').value.trim();
  const pass  = document.getElementById('newUserPass').value.trim();
  const role  = document.getElementById('newUserRole').value;

  if (!uname || !pass) { showToastError('Please enter username and password'); return; }
  if (users.find(u => u.username === uname)) { showToastError('Username already exists'); return; }

  users.push({ username: uname, role, password: pass, addedOn: new Date().toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}) });
  document.getElementById('statUsers').textContent = users.length;

  removeEmptyRow('userTable');
  const row = document.createElement('tr');
  row.dataset.username = uname;
  const roleBadge = role === 'admin'
    ? '<span class="role-badge badge-admin-sm">Administrator</span>'
    : '<span class="role-badge badge-user-sm">Standard User</span>';
  row.innerHTML = `
    <td>${escHtml(uname)}</td>
    <td>${roleBadge}</td>
    <td><span class="status-badge status-active"><span class="status-dot-small"></span>Active</span></td>
    <td>${users[users.length-1].addedOn}</td>
    <td><button class="btn-remove" onclick="removeUser(this,'${escHtml(uname)}')">Remove</button></td>`;
  document.getElementById('userTable').prepend(row);

  addAuditEntry('admin', 'USER_ADDED', `User "${uname}" (${role}) created`, 'SUCCESS');
  addActivity(`<span>admin</span> added new user <span>${escHtml(uname)}</span>`);

  document.getElementById('newUsername').value = '';
  document.getElementById('newUserPass').value = '';
  showToast(`User "${uname}" added successfully`);
}

function removeUser(btn, uname) {
  const idx = users.findIndex(u => u.username === uname);
  if (idx > -1) users.splice(idx, 1);
  document.getElementById('statUsers').textContent = users.length;
  btn.closest('tr').remove();
  addAuditEntry('admin', 'USER_REMOVED', `User "${uname}" removed`, 'SUCCESS');
  addActivity(`<span>admin</span> removed user <span>${escHtml(uname)}</span>`);
  showToast(`User "${uname}" removed`);
}

// ══════════════════════════════════════════
//  ACTIVITY FEED
// ══════════════════════════════════════════
function addActivity(text) {
  const feed = document.getElementById('recentActivity');
  const empty = feed.querySelector('.activity-empty');
  if (empty) empty.remove();

  const time = new Date().toLocaleTimeString('en-US', { hour:'2-digit', minute:'2-digit' });
  const item = document.createElement('div');
  item.className = 'activity-item';
  item.innerHTML = `
    <div class="activity-dot"></div>
    <div class="activity-text">${text}</div>
    <div class="activity-time">${time}</div>`;

  feed.insertBefore(item, feed.firstChild);

  const items = feed.querySelectorAll('.activity-item');
  if (items.length > 8) items[items.length - 1].remove();
}

// ══════════════════════════════════════════
//  AUDIT LOG
// ══════════════════════════════════════════
function addAuditEntry(user, action, details, status) {
  removeEmptyRow('auditLog');
  const ts = nowTimestamp();
  const actionClasses = {
    UPLOAD: 'action-upload', DOWNLOAD: 'action-download',
    LOGIN:  'action-login',  LOGOUT:   'action-logout',
    USER_ADDED: 'action-user', USER_REMOVED: 'action-user',
  };
  const cls = actionClasses[action] || 'action-upload';
  const row = document.createElement('tr');
  row.dataset.action = action;
  row.dataset.details = (user + ' ' + details).toLowerCase();
  row.innerHTML = `
    <td style="font-size:11px;color:var(--text-dim)">${ts}</td>
    <td>${escHtml(user)}</td>
    <td><span class="audit-action ${cls}">${action.replace('_',' ')}</span></td>
    <td style="font-size:11px">${escHtml(details)}</td>
    <td><span class="status-badge status-active"><span class="status-dot-small"></span>${status}</span></td>`;
  document.getElementById('auditLog').prepend(row);
}

// ══════════════════════════════════════════
//  SEARCH & FILTER
// ══════════════════════════════════════════
function filterTable(tbodyId, searchId, dateId, typeId) {
  const query   = document.getElementById(searchId).value.trim().toLowerCase();
  const dateVal = document.getElementById(dateId).value;
  const typeVal = typeId ? document.getElementById(typeId).value : '';
  const rows    = document.querySelectorAll('#' + tbodyId + ' tr:not(.empty-row)');
  let visible   = 0;

  rows.forEach(row => {
    const nm = !query   || row.dataset.name.includes(query);
    const dt = !dateVal || row.dataset.date === dateVal;
    const tp = !typeVal || row.dataset.type === typeVal;
    const show = nm && dt && tp;
    row.classList.toggle('hidden-row', !show);
    if (show) visible++;
  });

  const noResultsMap = {
    adminOriginalFiles:  'adminOrigNoResults',
    adminSanitizedFiles: 'adminSanNoResults',
    userSanitizedFiles:  'userSanNoResults',
  };
  const noEl = document.getElementById(noResultsMap[tbodyId]);
  if (noEl) noEl.style.display = (visible === 0 && rows.length > 0) ? 'block' : 'none';
}

function filterAudit() {
  const query  = document.getElementById('auditSearch').value.trim().toLowerCase();
  const action = document.getElementById('auditActionFilter').value;
  const rows   = document.querySelectorAll('#auditLog tr:not(.empty-row)');
  let visible  = 0;

  rows.forEach(row => {
    const am = !action || row.dataset.action === action;
    const qm = !query  || row.dataset.details.includes(query);
    const show = am && qm;
    row.classList.toggle('hidden-row', !show);
    if (show) visible++;
  });

  const noEl = document.getElementById('auditNoResults');
  if (noEl) noEl.style.display = (visible === 0 && rows.length > 0) ? 'block' : 'none';
}

// ══════════════════════════════════════════
//  TOAST
// ══════════════════════════════════════════
function showToast(msg) {
  const t = document.getElementById('toast');
  t.style.borderColor = 'var(--cyan)'; t.style.color = 'var(--cyan)';
  document.getElementById('toastMsg').textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

function showToastError(msg) {
  const t = document.getElementById('toast');
  t.style.borderColor = 'var(--red)'; t.style.color = 'var(--red)';
  document.getElementById('toastMsg').textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}