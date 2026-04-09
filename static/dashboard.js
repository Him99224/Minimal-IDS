/**
 * Minimal IDS — Dashboard Client
 * Real-time threat visualization via WebSocket
 */

(function () {
    'use strict';

    // ---------------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------------
    let authToken = null;
    let ws = null;
    let wsRetryTimer = null;
    const WS_RETRY_MS = 3000;
    let threatEvents = [];        // newest first
    let threatTypeCounts = {};
    const MAX_FEED_ITEMS = 200;

    // Severity colour map
    const SEV_COLORS = {
        LOW:    '#38bdf8',
        MEDIUM: '#fbbf24',
        HIGH:   '#f97316',
        SEVERE: '#ef4444',
    };

    // Chart colour palette for threat types
    const CHART_PALETTE = [
        '#818cf8', '#f97316', '#ef4444', '#38bdf8', '#34d399',
        '#fbbf24', '#a78bfa', '#f472b6', '#22d3ee', '#fb923c',
        '#4ade80',
    ];

    // ---------------------------------------------------------------------------
    // DOM refs
    // ---------------------------------------------------------------------------
    const $ = (id) => document.getElementById(id);

    const loginOverlay   = $('loginOverlay');
    const loginForm      = $('loginForm');
    const loginError     = $('loginError');
    const loginBtn       = $('loginBtn');
    const dashContainer  = $('dashboardContainer');

    const wsDot          = $('wsDot');
    const wsLabel        = $('wsLabel');

    const statThreats    = $('statThreats');
    const statBlocked    = $('statBlocked');
    const statUsers      = $('statUsers');
    const statWsClients  = $('statWsClients');

    const feedCount      = $('feedCount');
    const threatFeed     = $('threatFeed');
    const feedEmpty      = $('feedEmpty');

    const donutCanvas    = $('donutChart');
    const chartTotal     = $('chartTotal');
    const chartLegend    = $('chartLegend');

    const userTableBody  = $('userTableBody');
    const userCount      = $('userCount');

    const simStatus      = $('simStatus');

    // ---------------------------------------------------------------------------
    // Login
    // ---------------------------------------------------------------------------
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.classList.remove('visible');
        loginBtn.textContent = 'Signing in…';
        loginBtn.disabled = true;

        const username = $('loginUsername').value.trim();
        const password = $('loginPassword').value;

        try {
            const res = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Login failed');
            }

            const data = await res.json();
            authToken = data.access_token;

            // Verify overseer role by decoding JWT payload (base64)
            const payloadB64 = authToken.split('.')[1];
            const payload = JSON.parse(atob(payloadB64));
            if (payload.role !== 'overseer') {
                throw new Error('Overseer role required. Use admin credentials.');
            }

            loginOverlay.classList.add('hidden');
            dashContainer.style.display = 'block';
            initDashboard();
        } catch (err) {
            loginError.textContent = err.message;
            loginError.classList.add('visible');
        } finally {
            loginBtn.textContent = 'Sign In';
            loginBtn.disabled = false;
        }
    });

    // ---------------------------------------------------------------------------
    // Dashboard init
    // ---------------------------------------------------------------------------
    function initDashboard() {
        connectWebSocket();
        loadInitialData();
        // Refresh user table periodically
        setInterval(loadUsers, 5000);
    }

    // ---------------------------------------------------------------------------
    // WebSocket
    // ---------------------------------------------------------------------------
    function connectWebSocket() {
        if (ws && ws.readyState <= 1) return;

        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        ws = new WebSocket(`${proto}://${location.host}/ws/events`);

        ws.onopen = () => {
            wsDot.classList.add('connected');
            wsLabel.textContent = 'Connected';
            if (wsRetryTimer) { clearInterval(wsRetryTimer); wsRetryTimer = null; }
        };

        ws.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
                if (msg.type === 'threat_event') {
                    handleThreatEvent(msg.event, msg.stats);
                }
            } catch (_) { /* ignore bad frames */ }
        };

        ws.onclose = () => {
            wsDot.classList.remove('connected');
            wsLabel.textContent = 'Reconnecting…';
            if (!wsRetryTimer) {
                wsRetryTimer = setInterval(() => connectWebSocket(), WS_RETRY_MS);
            }
        };

        ws.onerror = () => ws.close();
    }

    // ---------------------------------------------------------------------------
    // Data loading
    // ---------------------------------------------------------------------------
    async function loadInitialData() {
        try {
            const [statsRes, threatsRes] = await Promise.all([
                fetch('/api/stats'),
                fetch('/api/threats/recent?limit=50'),
            ]);
            const stats = await statsRes.json();
            const threats = await threatsRes.json();

            // Populate feed from history
            threatTypeCounts = stats.threat_type_counts || {};
            threatEvents = threats;
            updateStats(stats);
            renderFeed();
            renderChart();
            loadUsers();
        } catch (e) {
            console.error('Failed to load initial data', e);
        }
    }

    async function loadUsers() {
        try {
            const res = await fetch('/api/users');
            const users = await res.json();
            renderUserTable(users);
        } catch (_) { /* swallow */ }
    }

    // ---------------------------------------------------------------------------
    // Event handling
    // ---------------------------------------------------------------------------
    function handleThreatEvent(event, stats) {
        // Prepend to events array
        threatEvents.unshift(event);
        if (threatEvents.length > MAX_FEED_ITEMS) threatEvents.pop();

        // Update counts
        const tt = event.threat_type;
        threatTypeCounts[tt] = (threatTypeCounts[tt] || 0) + 1;

        // Update UI
        updateStats(stats);
        prependFeedItem(event);
        renderChart();

        // Refresh users to catch new blocks
        loadUsers();
    }

    // ---------------------------------------------------------------------------
    // Stats
    // ---------------------------------------------------------------------------
    function updateStats(stats) {
        animateValue(statThreats, stats.total_threats);
        animateValue(statBlocked, stats.blocked_users);
        animateValue(statUsers, stats.tracked_users);
        if (stats.active_ws_clients !== undefined) {
            animateValue(statWsClients, stats.active_ws_clients);
        }
    }

    function animateValue(el, newVal) {
        const current = parseInt(el.textContent, 10) || 0;
        if (current === newVal) return;
        el.textContent = newVal;
        el.closest('.stat-card')?.classList.remove('flash-update');
        void el.closest('.stat-card')?.offsetWidth; // reflow
        el.closest('.stat-card')?.classList.add('flash-update');
    }

    // ---------------------------------------------------------------------------
    // Threat Feed
    // ---------------------------------------------------------------------------
    function renderFeed() {
        if (threatEvents.length === 0) {
            feedEmpty.style.display = 'block';
            feedCount.textContent = '0 events';
            return;
        }
        feedEmpty.style.display = 'none';
        feedCount.textContent = `${threatEvents.length} events`;

        const fragment = document.createDocumentFragment();
        for (const evt of threatEvents) {
            fragment.appendChild(createFeedItem(evt, false));
        }
        // Clear old items and add new
        const empNode = feedEmpty;
        threatFeed.innerHTML = '';
        threatFeed.appendChild(empNode);
        threatFeed.appendChild(fragment);
    }

    function prependFeedItem(event) {
        feedEmpty.style.display = 'none';
        feedCount.textContent = `${threatEvents.length} events`;
        const item = createFeedItem(event, true);
        // Insert after empty placeholder
        if (feedEmpty.nextSibling) {
            threatFeed.insertBefore(item, feedEmpty.nextSibling);
        } else {
            threatFeed.appendChild(item);
        }

        // Cap visible items
        while (threatFeed.children.length > MAX_FEED_ITEMS + 1) {
            threatFeed.removeChild(threatFeed.lastChild);
        }
    }

    function createFeedItem(event, animate) {
        const sev = event.severity || 'LOW';
        const div = document.createElement('div');
        div.className = 'threat-item';
        if (!animate) div.style.animation = 'none';

        const timeStr = formatTime(event.timestamp);
        div.innerHTML = `
            <div class="threat-severity-indicator ${sev}"></div>
            <div class="threat-content">
                <div class="threat-type">${escHtml(event.threat_type)}</div>
                <div class="threat-meta">
                    <span>👤 ${escHtml(event.user_id)}</span>
                    <span>🌐 ${escHtml(event.ip_address)}</span>
                    <span>🕐 ${timeStr}</span>
                    ${event.is_auto_block ? '<span style="color:var(--color-severe)">🚫 AUTO-BLOCKED</span>' : ''}
                </div>
            </div>
            <div class="threat-points ${sev}">+${event.points_added}</div>
        `;
        return div;
    }

    // ---------------------------------------------------------------------------
    // Donut Chart (Canvas)
    // ---------------------------------------------------------------------------
    function renderChart() {
        const entries = Object.entries(threatTypeCounts).sort((a, b) => b[1] - a[1]);
        const total = entries.reduce((s, e) => s + e[1], 0);
        chartTotal.textContent = total;

        const ctx = donutCanvas.getContext('2d');
        const size = 200;
        const cx = size / 2, cy = size / 2;
        const outerR = 90, innerR = 60;

        ctx.clearRect(0, 0, size, size);

        if (total === 0) {
            // Empty state ring
            ctx.beginPath();
            ctx.arc(cx, cy, (outerR + innerR) / 2, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(255,255,255,0.06)';
            ctx.lineWidth = outerR - innerR;
            ctx.stroke();
            chartLegend.innerHTML = '<div style="text-align:center;color:var(--text-muted);font-size:0.8rem;padding:8px;">No data</div>';
            return;
        }

        let startAngle = -Math.PI / 2;
        entries.forEach(([type, count], i) => {
            const sweep = (count / total) * Math.PI * 2;
            const color = CHART_PALETTE[i % CHART_PALETTE.length];

            ctx.beginPath();
            ctx.arc(cx, cy, outerR, startAngle, startAngle + sweep);
            ctx.arc(cx, cy, innerR, startAngle + sweep, startAngle, true);
            ctx.closePath();
            ctx.fillStyle = color;
            ctx.fill();

            startAngle += sweep;
        });

        // Legend
        chartLegend.innerHTML = entries.map(([type, count], i) => {
            const color = CHART_PALETTE[i % CHART_PALETTE.length];
            const pct = ((count / total) * 100).toFixed(0);
            return `<div class="legend-item">
                <span class="legend-color" style="background:${color}"></span>
                <span class="legend-label">${formatThreatName(type)}</span>
                <span class="legend-value">${count} (${pct}%)</span>
            </div>`;
        }).join('');
    }

    // ---------------------------------------------------------------------------
    // User Table
    // ---------------------------------------------------------------------------
    function renderUserTable(users) {
        userCount.textContent = `${users.length} users`;
        if (users.length === 0) {
            userTableBody.innerHTML = '<tr><td colspan="6" class="user-table-empty">No users tracked yet.</td></tr>';
            return;
        }

        // Sort: blocked first, then by score descending
        users.sort((a, b) => {
            if (a.is_blocked !== b.is_blocked) return a.is_blocked ? -1 : 1;
            return b.current_score - a.current_score;
        });

        userTableBody.innerHTML = users.map((u) => {
            const scoreClass = u.current_score >= 61 ? 'severe'
                : u.current_score >= 31 ? 'high'
                : u.current_score >= 10 ? 'medium'
                : 'low';
            const barWidth = Math.min(100, (u.current_score / 100) * 100);
            const statusBadge = u.is_blocked
                ? '<span class="status-badge blocked">🚫 Blocked</span>'
                : '<span class="status-badge active">✓ Active</span>';
            const actions = u.is_blocked
                ? `<button class="action-btn success" onclick="userAction('${u.user_id}','unblock')">Unblock</button>`
                : `<button class="action-btn danger" onclick="userAction('${u.user_id}','block')">Block</button>`;

            return `<tr class="${u.is_blocked ? 'user-row-blocked' : ''}">
                <td class="user-id-cell">${escHtml(u.user_id)}</td>
                <td>${u.current_score.toFixed(1)}</td>
                <td>
                    <div class="score-bar-container">
                        <div class="score-bar-fill ${scoreClass}" style="width:${barWidth}%"></div>
                    </div>
                </td>
                <td>${u.threat_count}</td>
                <td>${statusBadge}</td>
                <td>
                    ${actions}
                    <button class="action-btn" onclick="userAction('${u.user_id}','clear')">Clear</button>
                </td>
            </tr>`;
        }).join('');
    }

    // ---------------------------------------------------------------------------
    // User Actions (block / unblock / clear)
    // ---------------------------------------------------------------------------
    window.userAction = async function (userId, action) {
        try {
            const url = `/overseer/users/${encodeURIComponent(userId)}/${action}`;
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${authToken}` },
            });
            if (!res.ok) {
                const err = await res.json();
                alert(err.detail || 'Action failed');
                return;
            }
            loadUsers();
            // Also refresh stats
            const statsRes = await fetch('/api/stats');
            const stats = await statsRes.json();
            updateStats(stats);
        } catch (e) {
            alert('Action failed: ' + e.message);
        }
    };

    // ---------------------------------------------------------------------------
    // Simulator controls
    // ---------------------------------------------------------------------------
    window.runSimulation = async function (mode) {
        const btnStag = $('btnSimStaggered');
        const btnInst = $('btnSimInstant');
        btnStag.disabled = btnInst.disabled = true;

        simStatus.textContent = mode === 'staggered'
            ? '🔄 Running staggered attack simulation… events will appear live.'
            : '⚡ Firing instant burst…';

        try {
            const res = await fetch(`/demo/simulate?mode=${mode}&count=20`, { method: 'POST' });
            const data = await res.json();
            simStatus.textContent = `✅ ${data.message}`;
        } catch (e) {
            simStatus.textContent = `❌ Simulation failed: ${e.message}`;
        } finally {
            btnStag.disabled = btnInst.disabled = false;
        }
    };

    window.resetDemo = async function () {
        const btnReset = $('btnSimReset');
        btnReset.disabled = true;
        simStatus.textContent = '🔄 Resetting all state…';

        try {
            const res = await fetch('/demo/reset', { method: 'POST' });
            const data = await res.json();
            simStatus.textContent = `✅ ${data.message}`;

            // Clear local state
            threatEvents = [];
            threatTypeCounts = {};
            renderFeed();
            renderChart();
            updateStats({ total_threats: 0, blocked_users: 0, tracked_users: 0, active_ws_clients: 0 });
            loadUsers();
        } catch (e) {
            simStatus.textContent = `❌ Reset failed: ${e.message}`;
        } finally {
            btnReset.disabled = false;
        }
    };

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------
    function formatTime(ts) {
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch (_) {
            return ts;
        }
    }

    function formatThreatName(type) {
        return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    }

    function escHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

})();
