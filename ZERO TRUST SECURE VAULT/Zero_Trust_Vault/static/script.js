/* ═══════════════════════════════════════════════════════════════════════════
   script.js — Zero Trust Secure Vault :: Premium Frontend Controller v2
   ═══════════════════════════════════════════════════════════════════════════ */

// ---------------------------------------------------------------------------
// Global State
// ---------------------------------------------------------------------------
let selectedFile  = null;
let shareFilename = '';
let currentView   = 'list';
let searchTimeout = null;


// ═══════════════════════════════════════════════════════════════════════════
// FILE TYPE COLOUR SYSTEM
// ═══════════════════════════════════════════════════════════════════════════
const FILE_TYPE_COLORS = {
    // Documents
    pdf:  { accent: '#ef4444', bg: 'rgba(239,68,68,0.07)',  border: 'rgba(239,68,68,0.12)' },
    doc:  { accent: '#3b82f6', bg: 'rgba(59,130,246,0.07)', border: 'rgba(59,130,246,0.12)' },
    docx: { accent: '#3b82f6', bg: 'rgba(59,130,246,0.07)', border: 'rgba(59,130,246,0.12)' },
    txt:  { accent: '#6366f1', bg: 'rgba(99,102,241,0.07)', border: 'rgba(99,102,241,0.12)' },
    md:   { accent: '#6366f1', bg: 'rgba(99,102,241,0.07)', border: 'rgba(99,102,241,0.12)' },
    // Images
    jpg:  { accent: '#ec4899', bg: 'rgba(236,72,153,0.07)', border: 'rgba(236,72,153,0.12)' },
    jpeg: { accent: '#ec4899', bg: 'rgba(236,72,153,0.07)', border: 'rgba(236,72,153,0.12)' },
    png:  { accent: '#ec4899', bg: 'rgba(236,72,153,0.07)', border: 'rgba(236,72,153,0.12)' },
    gif:  { accent: '#ec4899', bg: 'rgba(236,72,153,0.07)', border: 'rgba(236,72,153,0.12)' },
    webp: { accent: '#ec4899', bg: 'rgba(236,72,153,0.07)', border: 'rgba(236,72,153,0.12)' },
    svg:  { accent: '#ec4899', bg: 'rgba(236,72,153,0.07)', border: 'rgba(236,72,153,0.12)' },
    bmp:  { accent: '#ec4899', bg: 'rgba(236,72,153,0.07)', border: 'rgba(236,72,153,0.12)' },
    // Code
    py:   { accent: '#22c55e', bg: 'rgba(34,197,94,0.07)',  border: 'rgba(34,197,94,0.12)' },
    js:   { accent: '#eab308', bg: 'rgba(234,179,8,0.07)',  border: 'rgba(234,179,8,0.12)' },
    ts:   { accent: '#3b82f6', bg: 'rgba(59,130,246,0.07)', border: 'rgba(59,130,246,0.12)' },
    html: { accent: '#f97316', bg: 'rgba(249,115,22,0.07)', border: 'rgba(249,115,22,0.12)' },
    css:  { accent: '#06b6d4', bg: 'rgba(6,182,212,0.07)',  border: 'rgba(6,182,212,0.12)' },
    // Data
    json: { accent: '#a855f7', bg: 'rgba(168,85,247,0.07)', border: 'rgba(168,85,247,0.12)' },
    csv:  { accent: '#22c55e', bg: 'rgba(34,197,94,0.07)',  border: 'rgba(34,197,94,0.12)' },
    xml:  { accent: '#f97316', bg: 'rgba(249,115,22,0.07)', border: 'rgba(249,115,22,0.12)' },
    xlsx: { accent: '#22c55e', bg: 'rgba(34,197,94,0.07)',  border: 'rgba(34,197,94,0.12)' },
    // Archives
    zip:  { accent: '#f59e0b', bg: 'rgba(245,158,11,0.07)', border: 'rgba(245,158,11,0.12)' },
    rar:  { accent: '#f59e0b', bg: 'rgba(245,158,11,0.07)', border: 'rgba(245,158,11,0.12)' },
    '7z': { accent: '#f59e0b', bg: 'rgba(245,158,11,0.07)', border: 'rgba(245,158,11,0.12)' },
    // Media
    mp4:  { accent: '#a855f7', bg: 'rgba(168,85,247,0.07)', border: 'rgba(168,85,247,0.12)' },
    mp3:  { accent: '#a855f7', bg: 'rgba(168,85,247,0.07)', border: 'rgba(168,85,247,0.12)' },
    wav:  { accent: '#a855f7', bg: 'rgba(168,85,247,0.07)', border: 'rgba(168,85,247,0.12)' },
    // Presentations
    pptx: { accent: '#f97316', bg: 'rgba(249,115,22,0.07)', border: 'rgba(249,115,22,0.12)' },
};

const DEFAULT_COLOR = { accent: '#6b7280', bg: 'rgba(107,114,128,0.07)', border: 'rgba(107,114,128,0.12)' };

function getFileTypeColor(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    return FILE_TYPE_COLORS[ext] || DEFAULT_COLOR;
}


// ═══════════════════════════════════════════════════════════════════════════
// SECTION NAVIGATION
// ═══════════════════════════════════════════════════════════════════════════

function switchSection(section, navElement) {
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const el = document.getElementById(`section-${section}`);
    if (el) el.classList.add('active');
    if (navElement) navElement.classList.add('active');

    const titles = { 'my-drive': 'My Drive', 'shared': 'Shared with me', 'audit': 'Audit Logs' };
    document.getElementById('page-title').textContent = titles[section] || 'Dashboard';

    if (section === 'my-drive') loadFiles();
    if (section === 'shared')   loadSharedFiles();
    if (section === 'audit')    loadAuditLogs();

    document.getElementById('sidebar').classList.remove('open');
}

function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }


// ═══════════════════════════════════════════════════════════════════════════
// VIEW TOGGLE
// ═══════════════════════════════════════════════════════════════════════════

function setView(view) {
    currentView = view;
    const grids = [document.getElementById('file-grid'), document.getElementById('shared-grid')];
    
    document.querySelectorAll('.view-toggle').forEach(b => {
        b.classList.toggle('active', b.id.endsWith(`-${view}`));
    });

    grids.forEach(g => {
        if (g) {
            g.classList.toggle('list-view', view === 'list');
            g.classList.toggle('grid-view', view === 'grid');
        }
    });
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE LISTING
// ═══════════════════════════════════════════════════════════════════════════

async function loadFiles() {
    const grid  = document.getElementById('file-grid');
    const empty = document.getElementById('empty-state');
    const count = document.getElementById('file-count');

    // Show skeleton loading state
    grid.innerHTML = generateSkeletons(4);
    empty.style.display = 'none';

    try {
        const res  = await fetch('/api/files');
        const data = await res.json();

        if (!data.files || data.files.length === 0) {
            grid.innerHTML = '';
            empty.style.display = 'flex';
            animateCounter(count, 0, 'files');
            return;
        }

        empty.style.display = 'none';
        animateCounter(count, data.files.length, 'file');
        // Staggered card rendering
        grid.innerHTML = data.files.map((f, i) =>
            createFileCard(f, false, i)
        ).join('');
    } catch (err) {
        console.error('Failed to load files:', err);
        showToast('Failed to load files.', 'error');
        grid.innerHTML = '';
    }
}

/**
 * Generate skeleton loading placeholder cards
 */
function generateSkeletons(count) {
    return Array.from({ length: count }, (_, i) => `
        <div class="skeleton-card" style="animation-delay: ${i * 0.08}s">
            <div class="skeleton-icon"></div>
            <div class="skeleton-lines">
                <div class="skeleton-line"></div>
                <div class="skeleton-line"></div>
            </div>
        </div>
    `).join('');
}

/**
 * Animate a counter element from 0 to target value
 */
function animateCounter(el, target, unit) {
    if (!el) return;
    const suffix = target !== 1 ? unit + 's' : unit;
    if (target === 0) { el.textContent = `0 ${suffix}`; return; }
    let current = 0;
    const step = Math.max(1, Math.floor(target / 20));
    const interval = setInterval(() => {
        current = Math.min(current + step, target);
        const s = current !== 1 ? unit + 's' : unit;
        el.textContent = `${current} ${s}`;
        if (current >= target) clearInterval(interval);
    }, 30);
}

/**
 * Build a premium file card with type-based colour accents.
 */
function createFileCard(file, isShared = false, index = 0) {
    const icon  = getFileIcon(file.filename);
    const color = getFileTypeColor(file.filename);
    const size  = formatSize(file.size);
    const date  = formatDate(file.updated_at || file.shared_at || file.created_at);
    const fname = escapeHtml(file.filename);

    const ownerTag = isShared ? `<span class="sep"></span><span>from ${escapeHtml(file.owner)}</span>` : '';
    const versionTag = file.version_count > 1
        ? `<span class="sep"></span><span>v${file.current_version}</span>` : '';

    let actions;
    if (isShared) {
        const owner = escapeHtml(file.owner);
        actions = `
            <button class="action-btn" onclick="event.stopPropagation(); previewSharedFile('${owner}','${fname}')" title="Preview">👁</button>
            <button class="action-btn" onclick="event.stopPropagation(); downloadSharedFile('${owner}','${fname}')" title="Download">⬇</button>
            <button class="action-btn" onclick="event.stopPropagation(); showSharedVersions('${owner}','${fname}')" title="Versions">🕒</button>
            <button class="action-btn delete" onclick="event.stopPropagation(); deleteSharedFile('${owner}','${fname}')" title="Delete">🗑</button>
        `;
    } else {
        actions = `
            <button class="action-btn" onclick="event.stopPropagation(); previewFile('${fname}')" title="Preview">👁</button>
            <button class="action-btn" onclick="event.stopPropagation(); downloadFile('${fname}')" title="Download">⬇</button>
            <button class="action-btn" onclick="event.stopPropagation(); openShareModal('${fname}')" title="Share">🔗</button>
            <button class="action-btn" onclick="event.stopPropagation(); showVersions('${fname}')" title="Versions">🕒</button>
            <button class="action-btn delete" onclick="event.stopPropagation(); deleteFile('${fname}')" title="Delete">🗑</button>
        `;
    }

    const click = isShared
        ? `previewSharedFile('${escapeHtml(file.owner)}','${fname}')`
        : `previewFile('${fname}')`;

    // Inject type colours via CSS custom properties for the accent system
    return `
        <div class="file-card" onclick="${click}"
             style="--file-accent:${color.accent}; --file-accent-bg:${color.bg}; --file-accent-border:${color.border}; animation-delay: ${index * 0.05}s;">
            <div class="file-icon-wrap">${icon}</div>
            <div class="file-info">
                <div class="file-name">${fname}</div>
                <div class="file-meta">
                    <span>${size}</span>
                    <span class="sep"></span>
                    <span>${date}</span>
                    ${ownerTag}${versionTag}
                </div>
            </div>
            <div class="file-actions">${actions}</div>
        </div>
    `;
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE UPLOAD
// ═══════════════════════════════════════════════════════════════════════════

function openUploadModal() { clearSelectedFile(); openModal('upload-modal'); }

function handleDragOver(e) { e.preventDefault(); e.currentTarget.classList.add('drag-over'); }
function handleDragLeave(e) { e.currentTarget.classList.remove('drag-over'); }
function handleDrop(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) setSelectedFile(e.dataTransfer.files[0]);
}
function handleFileSelect(e) {
    if (e.target.files.length > 0) setSelectedFile(e.target.files[0]);
}

function setSelectedFile(file) {
    selectedFile = file;
    document.getElementById('drop-zone').style.display = 'none';
    document.getElementById('selected-file').style.display = 'flex';
    document.getElementById('selected-file-name').textContent = file.name;
    document.getElementById('selected-file-size').textContent = formatSize(file.size);
    document.getElementById('upload-submit').disabled = false;
}

function clearSelectedFile() {
    selectedFile = null;
    document.getElementById('drop-zone').style.display = 'block';
    document.getElementById('selected-file').style.display = 'none';
    document.getElementById('upload-progress').style.display = 'none';
    document.getElementById('upload-submit').disabled = true;
    document.getElementById('file-input').value = '';
}

async function uploadFile() {
    if (!selectedFile) return;

    const btn = document.getElementById('upload-submit');
    const progress = document.getElementById('upload-progress');
    const fill = document.getElementById('progress-fill');
    const text = document.getElementById('progress-text');

    btn.classList.add('loading');
    btn.disabled = true;
    progress.style.display = 'block';
    fill.style.width = '30%';
    text.textContent = 'Reading file bytes...';

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
        fill.style.width = '60%';
        text.textContent = 'Encrypting with AES-256...';

        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await res.json();

        if (res.ok) {
            fill.style.width = '100%';
            text.textContent = 'Encryption complete ✓';
            showToast(`"${data.filename}" encrypted & stored (v${data.version})`, 'success');
            setTimeout(() => { closeModal('upload-modal'); clearSelectedFile(); loadFiles(); loadStorageInfo(); }, 800);
        } else {
            if (data.quota_exceeded) document.getElementById('quota-banner').style.display = 'flex';
            showToast(data.error || 'Upload failed.', 'error');
            progress.style.display = 'none';
        }
    } catch { showToast('Network error during upload.', 'error'); progress.style.display = 'none'; }
    finally { btn.classList.remove('loading'); btn.disabled = false; }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE DOWNLOAD
// ═══════════════════════════════════════════════════════════════════════════

async function downloadFile(filename, version = null) {
    try {
        let url = `/api/download/${encodeURIComponent(filename)}`;
        if (version) url += `/${version}`;
        const res = await fetch(url);
        if (!res.ok) {
            const data = await res.json();
            if (data.tampering) { showTamperingAlert(filename, data.message); return; }
            showToast(data.error || 'Download failed.', 'error'); return;
        }
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
        showToast(`"${filename}" downloaded & integrity verified ✓`, 'success');
    } catch { showToast('Download error.', 'error'); }
}

async function downloadSharedFile(owner, filename, version = null) {
    try {
        let url = `/api/shared/download/${encodeURIComponent(owner)}/${encodeURIComponent(filename)}`;
        if (version) url += `/${version}`;
        const res = await fetch(url);
        if (!res.ok) {
            const data = await res.json();
            if (data.tampering) { showTamperingAlert(filename, data.message); return; }
            if (data.expired) { showToast('This share has expired.', 'warning'); return; }
            showToast(data.error || 'Download failed.', 'error'); return;
        }
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
        const versionMsg = version ? ` v${version}` : '';
        showToast(`Shared file "${filename}"${versionMsg} downloaded ✓`, 'success');
    } catch { showToast('Download error.', 'error'); }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE DELETE
// ═══════════════════════════════════════════════════════════════════════════

async function deleteFile(filename) {
    if (!confirm(`Delete "${filename}" and all its versions? This cannot be undone.`)) return;
    try {
        const res = await fetch(`/api/delete/${encodeURIComponent(filename)}`, { method: 'DELETE' });
        const data = await res.json();
        if (res.ok) { showToast(data.message, 'success'); loadFiles(); loadStorageInfo(); }
        else showToast(data.error || 'Delete failed.', 'error');
    } catch { showToast('Delete error.', 'error'); }
}


// ═══════════════════════════════════════════════════════════════════════════
// FILE PREVIEW
// ═══════════════════════════════════════════════════════════════════════════

async function previewFile(filename, version = null) {
    openModal('preview-modal');
    document.getElementById('preview-title').textContent = filename;
    document.getElementById('preview-loading').style.display = 'block';
    document.getElementById('preview-content').classList.remove('show');
    document.getElementById('preview-content').innerHTML = '';
    document.getElementById('preview-download-btn').onclick = () => downloadFile(filename, version);

    try {
        let url = `/api/preview/${encodeURIComponent(filename)}`;
        if (version) url += `/${version}`;
        const res = await fetch(url);
        if (!res.ok) {
            const data = await res.json();
            if (data.tampering) { closeModal('preview-modal'); showTamperingAlert(filename, data.message); return; }
            showPreviewError(data.error || 'Preview failed.'); return;
        }
        renderPreview(await res.blob(), res.headers.get('Content-Type') || '', filename);
    } catch { showPreviewError('Failed to load preview.'); }
}

async function previewSharedFile(owner, filename, version = null) {
    openModal('preview-modal');
    document.getElementById('preview-title').textContent = version
        ? `${filename} (v${version} from ${owner})`
        : `${filename} (from ${owner})`;
    document.getElementById('preview-loading').style.display = 'block';
    document.getElementById('preview-content').classList.remove('show');
    document.getElementById('preview-content').innerHTML = '';
    document.getElementById('preview-download-btn').onclick = () => downloadSharedFile(owner, filename, version);

    try {
        let url = `/api/shared/preview/${encodeURIComponent(owner)}/${encodeURIComponent(filename)}`;
        if (version) url += `/${version}`;
        const res = await fetch(url);
        if (!res.ok) {
            const data = await res.json();
            if (data.tampering) { closeModal('preview-modal'); showTamperingAlert(filename, data.message); return; }
            if (data.expired) { showPreviewError('This share has expired.'); return; }
            showPreviewError(data.error || 'Preview failed.'); return;
        }
        renderPreview(await res.blob(), res.headers.get('Content-Type') || '', filename);
    } catch { showPreviewError('Failed to load preview.'); }
}

function renderPreview(blob, contentType, filename) {
    const content = document.getElementById('preview-content');
    document.getElementById('preview-loading').style.display = 'none';

    if (contentType.startsWith('text/') || isTextFile(filename)) {
        const reader = new FileReader();
        reader.onload = () => {
            content.innerHTML = `<pre>${escapeHtml(reader.result)}</pre>`;
            content.classList.add('show');
        };
        reader.readAsText(blob);
    } else if (contentType.startsWith('image/')) {
        const url = URL.createObjectURL(blob);
        content.innerHTML = `<img src="${url}" alt="${escapeHtml(filename)}" onload="URL.revokeObjectURL(this.src)">`;
        content.classList.add('show');
    } else if (contentType === 'application/pdf') {
        const url = URL.createObjectURL(blob);
        content.innerHTML = `<iframe src="${url}" style="width:100%;height:480px;border:none;border-radius:10px;" title="PDF Preview"></iframe>`;
        content.classList.add('show');
    } else {
        content.innerHTML = `
            <div class="preview-unsupported">
                <div class="unsupported-icon">📄</div>
                <p>Preview not available for this file type</p>
                <p style="font-size:11.5px;color:var(--text-tertiary);margin-top:6px;font-family:'JetBrains Mono',monospace;">
                    ${escapeHtml(contentType)}
                </p>
            </div>`;
        content.classList.add('show');
    }
}

function showPreviewError(msg) {
    document.getElementById('preview-loading').style.display = 'none';
    const c = document.getElementById('preview-content');
    c.innerHTML = `<div class="preview-unsupported"><div class="unsupported-icon">⚠️</div><p style="color:var(--error);font-weight:600;">${escapeHtml(msg)}</p></div>`;
    c.classList.add('show');
}


// ═══════════════════════════════════════════════════════════════════════════
// SHARING
// ═══════════════════════════════════════════════════════════════════════════

function openShareModal(filename) {
    shareFilename = filename;
    document.getElementById('share-file-name').textContent = `📄  ${filename}`;
    document.getElementById('share-email-input').value = '';
    document.getElementById('share-expiry').value = '';
    document.getElementById('share-alert').style.display = 'none';
    document.getElementById('autocomplete-dropdown').classList.remove('show');
    openModal('share-modal');
    document.getElementById('share-email-input').focus();
}

function handleUserSearch(query) {
    const dropdown = document.getElementById('autocomplete-dropdown');
    if (searchTimeout) clearTimeout(searchTimeout);
    if (!query || query.length < 1) { dropdown.classList.remove('show'); return; }

    searchTimeout = setTimeout(async () => {
        try {
            const res = await fetch(`/api/users/search?q=${encodeURIComponent(query)}`);
            const data = await res.json();
            if (data.users && data.users.length > 0) {
                dropdown.innerHTML = data.users.map(u => `
                    <div class="autocomplete-item" onclick="selectShareUser('${escapeHtml(u.email)}')">
                        <div class="autocomplete-avatar">${u.avatar}</div>
                        <span class="autocomplete-email">${escapeHtml(u.email)}</span>
                    </div>
                `).join('');
                dropdown.classList.add('show');
            } else { dropdown.classList.remove('show'); }
        } catch { dropdown.classList.remove('show'); }
    }, 150);
}

function selectShareUser(email) {
    document.getElementById('share-email-input').value = email;
    document.getElementById('autocomplete-dropdown').classList.remove('show');
}

async function shareFile() {
    const targetEmail = document.getElementById('share-email-input').value.trim().toLowerCase();
    const expiry = document.getElementById('share-expiry').value;
    const alertEl = document.getElementById('share-alert');
    const btn = document.getElementById('share-submit');

    if (!targetEmail) {
        alertEl.textContent = 'Please enter an email address.';
        alertEl.className = 'share-alert error';
        alertEl.style.display = 'block';
        return;
    }

    btn.classList.add('loading');
    try {
        const res = await fetch('/api/share', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_email: targetEmail, filename: shareFilename, expiry: expiry || null }),
        });
        const data = await res.json();
        if (res.ok) {
            alertEl.textContent = data.message;
            alertEl.className = 'share-alert success';
            alertEl.style.display = 'block';
            showToast(data.message, 'success');
            setTimeout(() => closeModal('share-modal'), 1500);
        } else {
            alertEl.textContent = data.error;
            alertEl.className = 'share-alert error';
            alertEl.style.display = 'block';
        }
    } catch {
        alertEl.textContent = 'Network error.';
        alertEl.className = 'share-alert error';
        alertEl.style.display = 'block';
    } finally { btn.classList.remove('loading'); }
}


// ═══════════════════════════════════════════════════════════════════════════
// SHARED FILES
// ═══════════════════════════════════════════════════════════════════════════

async function loadSharedFiles() {
    const grid = document.getElementById('shared-grid');
    const empty = document.getElementById('shared-empty');
    const count = document.getElementById('shared-count');
    const badge = document.getElementById('shared-badge');

    // Show skeleton loading
    grid.innerHTML = generateSkeletons(3);
    empty.style.display = 'none';

    try {
        const res = await fetch('/api/shared-files');
        const data = await res.json();

        if (!data.shared_files || data.shared_files.length === 0) {
            grid.innerHTML = '';
            empty.style.display = 'flex';
            count.textContent = '0 shared files';
            badge.style.display = 'none';
            return;
        }

        empty.style.display = 'none';
        animateCounter(count, data.shared_files.length, 'shared file');
        badge.textContent = data.shared_files.length;
        badge.style.display = 'inline';
        grid.innerHTML = data.shared_files.map((f, i) => createFileCard(f, true, i)).join('');
    } catch (err) { console.error('Failed to load shared files:', err); }
}


// ═══════════════════════════════════════════════════════════════════════════
// VERSION HISTORY
// ═══════════════════════════════════════════════════════════════════════════

async function showVersions(filename) {
    document.getElementById('versions-title').textContent = `Version History — ${filename}`;
    openModal('versions-modal');
    try {
        const res = await fetch(`/api/file-versions/${encodeURIComponent(filename)}`);
        const data = await res.json();
        if (!res.ok) { showToast(data.error || 'Failed to load versions.', 'error'); return; }

        document.getElementById('versions-list').innerHTML = data.versions.map(v => `
            <div class="version-item">
                <div class="version-number">v${v.version}</div>
                <div class="version-info">
                    <div class="version-filename">${escapeHtml(v.encrypted_filename)}</div>
                    <div class="version-meta">${formatSize(v.size)} · ${formatDate(v.uploaded_at)} · SHA-256: ${v.original_hash.substring(0,12)}...</div>
                </div>
                <div class="version-actions">
                    <button class="action-btn" onclick="previewFile('${escapeHtml(filename)}',${v.version})" title="Preview">👁</button>
                    <button class="action-btn" onclick="downloadFile('${escapeHtml(filename)}',${v.version})" title="Download">⬇</button>
                </div>
            </div>
        `).join('');
    } catch { showToast('Error loading versions.', 'error'); }
}

async function showSharedVersions(owner, filename) {
    document.getElementById('versions-title').textContent = `Version History — ${filename} (from ${owner})`;
    openModal('versions-modal');
    try {
        const res = await fetch(`/api/shared/file-versions/${encodeURIComponent(owner)}/${encodeURIComponent(filename)}`);
        const data = await res.json();
        if (!res.ok) { showToast(data.error || 'Failed to load versions.', 'error'); return; }

        document.getElementById('versions-list').innerHTML = data.versions.map(v => `
            <div class="version-item">
                <div class="version-number">v${v.version}</div>
                <div class="version-info">
                    <div class="version-filename">${escapeHtml(v.encrypted_filename)}</div>
                    <div class="version-meta">${formatSize(v.size)} · ${formatDate(v.uploaded_at)} · SHA-256: ${v.original_hash.substring(0,12)}...</div>
                </div>
                <div class="version-actions">
                    <button class="action-btn" onclick="previewSharedFile('${escapeHtml(owner)}','${escapeHtml(filename)}',${v.version})" title="Preview">👁</button>
                    <button class="action-btn" onclick="downloadSharedFile('${escapeHtml(owner)}','${escapeHtml(filename)}',${v.version})" title="Download">⬇</button>
                </div>
            </div>
        `).join('');
    } catch { showToast('Error loading versions.', 'error'); }
}

async function deleteSharedFile(owner, filename) {
    if (!confirm(`Remove "${filename}" from your Shared with me list? This will revoke your access to this file.`)) return;
    try {
        const res = await fetch(`/api/shared/delete/${encodeURIComponent(owner)}/${encodeURIComponent(filename)}`, { method: 'DELETE' });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message, 'success');
            loadSharedFiles();
        } else {
            showToast(data.error || 'Remove failed.', 'error');
        }
    } catch { showToast('Remove error.', 'error'); }
}


// ═══════════════════════════════════════════════════════════════════════════
// AUDIT LOGS
// ═══════════════════════════════════════════════════════════════════════════

async function loadAuditLogs() {
    try {
        const filterOwn = document.getElementById('filter-own')?.checked ? 'true' : 'false';
        const res = await fetch(`/api/audit-logs?own=${filterOwn}`);
        const data = await res.json();
        const feed = document.getElementById('audit-feed');
        const count = document.getElementById('audit-count');

        if (!data.logs || data.logs.length === 0) {
            feed.innerHTML = '<div class="empty-state"><div class="empty-icon">📋</div><h3>No audit events yet</h3><p>Security events will appear here</p></div>';
            count.textContent = '0 events';
            return;
        }

        count.textContent = `${data.logs.length} event${data.logs.length !== 1 ? 's' : ''}`;
        feed.innerHTML = data.logs.map(log => {
            const cls = classificationToClass(log.classification);
            return `
                <div class="audit-entry ${cls}">
                    <span class="audit-badge">${escapeHtml(log.classification)}</span>
                    <div class="audit-body">
                        <div class="audit-action">${escapeHtml(log.action)}</div>
                        <div class="audit-details">${escapeHtml(log.details)}</div>
                        <div class="audit-footer">
                            <span class="audit-actor">${escapeHtml(log.actor)}</span>
                            <span>${formatDate(log.timestamp)}</span>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    } catch (err) { console.error('Failed to load audit logs:', err); }
}


// ═══════════════════════════════════════════════════════════════════════════
// STORAGE INFO
// ═══════════════════════════════════════════════════════════════════════════

async function loadStorageInfo() {
    try {
        const res = await fetch('/api/storage-info');
        const data = await res.json();
        const fill = document.getElementById('storage-fill');
        const text = document.getElementById('storage-text');

        fill.style.width = `${Math.min(data.percentage, 100)}%`;
        text.textContent = `${data.used_mb} MB of ${data.limit_mb} MB used`;

        fill.classList.remove('warning', 'critical');
        if (data.percentage > 90) {
            fill.classList.add('critical');
            document.getElementById('quota-banner').style.display = 'flex';
        } else if (data.percentage > 70) {
            fill.classList.add('warning');
        }

        // Update real-time storage details tooltip values
        const avail = (data.limit_mb - data.used_mb).toFixed(1);
        const availEl = document.getElementById('storage-available');
        const percentEl = document.getElementById('storage-percent-val');
        if (availEl) availEl.textContent = `${avail} MB`;
        if (percentEl) percentEl.textContent = `${Math.round(data.percentage)}%`;
    } catch (err) { console.error('Failed to load storage info:', err); }
}


// ═══════════════════════════════════════════════════════════════════════════
// TAMPERING ALERT
// ═══════════════════════════════════════════════════════════════════════════

function showTamperingAlert(filename, message) {
    document.getElementById('tamper-details').innerHTML =
        `File: ${escapeHtml(filename)}<br>Status: INTEGRITY CHECK FAILED<br>Action: Access DENIED`;
    openModal('tamper-modal');
    showToast('INTEGRITY TAMPERING DETECTED!', 'error');
}


// ═══════════════════════════════════════════════════════════════════════════
// MODAL MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

function openModal(id) {
    document.getElementById(id).classList.add('show');
    document.body.style.overflow = 'hidden';
}

function closeModal(id) {
    document.getElementById(id).classList.remove('show');
    if (!document.querySelector('.modal-overlay.show')) document.body.style.overflow = '';
}

document.addEventListener('click', e => {
    if (e.target.classList.contains('modal-overlay')) {
        e.target.classList.remove('show');
        if (!document.querySelector('.modal-overlay.show')) document.body.style.overflow = '';
    }
});

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay.show').forEach(m => m.classList.remove('show'));
        document.body.style.overflow = '';
    }
    // Ctrl+U keyboard shortcut for upload
    if ((e.ctrlKey || e.metaKey) && e.key === 'u') {
        e.preventDefault();
        openUploadModal();
    }
});


// ═══════════════════════════════════════════════════════════════════════════
// TOAST NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════════════════

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span class="toast-icon">${icons[type] || 'ℹ'}</span><span class="toast-message">${escapeHtml(message)}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.classList.add('removing'); setTimeout(() => toast.remove(), 300); }, 4000);
}


// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const map = {
        pdf:'📕', doc:'📘', docx:'📘', txt:'📝', md:'📝',
        jpg:'🖼️', jpeg:'🖼️', png:'🖼️', gif:'🎞️', webp:'🖼️', bmp:'🖼️', svg:'🎨',
        mp4:'🎬', avi:'🎬', mkv:'🎬', mov:'🎬',
        mp3:'🎵', wav:'🎵', flac:'🎵', ogg:'🎵',
        zip:'📦', rar:'📦', '7z':'📦', tar:'📦', gz:'📦',
        py:'🐍', js:'📜', ts:'📜', html:'🌐', css:'🎨',
        json:'📋', xml:'📋', csv:'📊', xlsx:'📊', xls:'📊',
        pptx:'📙', ppt:'📙', exe:'⚙️', dll:'⚙️', sh:'⚙️', bat:'⚙️',
    };
    return map[ext] || '📄';
}

function isTextFile(filename) {
    const exts = ['txt','md','py','js','ts','html','css','json','xml','csv','yaml','yml',
        'ini','cfg','conf','log','sh','bat','sql','java','c','cpp','h','hpp',
        'rb','php','go','rs','toml','env','gitignore','dockerfile'];
    return exts.includes(filename.split('.').pop().toLowerCase());
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024, sizes = ['B','KB','MB','GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(iso) {
    if (!iso) return '';
    try {
        const d = new Date(iso), now = new Date(), diff = now - d;
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
        if (diff < 604800000) return `${Math.floor(diff/86400000)}d ago`;
        return d.toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
    } catch { return iso; }
}

function classificationToClass(c) {
    return { 'SUCCESS':'success', 'WARNING':'warning', 'CRITICAL ALERT':'critical', 'INFO':'info' }[c] || 'info';
}

function escapeHtml(str) {
    if (!str) return '';
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}
