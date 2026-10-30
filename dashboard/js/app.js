/**
 * K-Sentinel Dashboard — Main Application
 * app.js
 *
 * Orchestrates the dashboard: connects the event stream to the UI,
 * manages state, updates stats, timeline, process table, and gauges.
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

(function () {
    'use strict';

    // ════════════════════════════════════════════════════════════════════
    // State
    // ════════════════════════════════════════════════════════════════════

    const state = {
        events: [],
        alerts: [],
        processes: new Map(), // pid -> { comm, ops, score, status, lastSeen }
        stats: {
            eventsReceived: 0,
            alertsGenerated: 0,
            processesKilled: 0,
            honeyfileHits: 0,
        },
        maxScore: 0,
        startTime: Date.now(),
        simulationActive: false,
        activeFilter: 'all',
    };

    // Syscall frequency accumulators (per second)
    const freqAccum = { open: 0, write: 0, rename: 0, unlink: 0 };

    // ════════════════════════════════════════════════════════════════════
    // Initialize Components
    // ════════════════════════════════════════════════════════════════════

    // Frequency chart
    const chart = new FrequencyChart('freq-canvas');

    // Event stream: simulated by default, real agent data with ?live=1
    const StreamClass = new URLSearchParams(location.search).has('live')
        ? LiveEventStream : EventStream;
    const stream = new StreamClass({
        interval: 800,
        onEvent: handleEvent,
        onAlert: handleAlert,
    });

    // ════════════════════════════════════════════════════════════════════
    // DOM References
    // ════════════════════════════════════════════════════════════════════

    const els = {
        statEvents:     document.getElementById('stat-events-value'),
        statAlerts:     document.getElementById('stat-alerts-value'),
        statKilled:     document.getElementById('stat-killed-value'),
        statHoneyfiles: document.getElementById('stat-honeyfiles-value'),
        statThreat:     document.getElementById('stat-threat-value'),
        threatCard:     document.getElementById('stat-threat'),
        uptimeValue:    document.getElementById('uptime-value'),
        gaugeFill:      document.getElementById('gauge-fill'),
        gaugeValue:     document.getElementById('gauge-value'),
        timeline:       document.getElementById('timeline-container'),
        timelineEmpty:  document.getElementById('timeline-empty'),
        processCount:   document.getElementById('process-count'),
        processTbody:   document.getElementById('process-tbody'),
        toastContainer: document.getElementById('toast-container'),
        btnSimulate:    document.getElementById('btn-toggle-sim'),
        btnClear:       document.getElementById('btn-clear'),
    };

    // ════════════════════════════════════════════════════════════════════
    // Event Handlers
    // ════════════════════════════════════════════════════════════════════

    function handleEvent(event) {
        state.events.push(event);
        state.stats.eventsReceived++;

        // Update frequency accumulator
        const typeMap = {
            'OPEN': 'open', 'WRITE': 'write',
            'RENAME': 'rename', 'UNLINK': 'unlink'
        };
        const accKey = typeMap[event.event_type];
        if (accKey) freqAccum[accKey]++;

        // Update process table state
        let proc = state.processes.get(event.pid);
        if (!proc) {
            proc = { comm: event.comm, ops: 0, score: 0, status: 'active', lastSeen: Date.now() };
            state.processes.set(event.pid, proc);
        }
        proc.ops++;
        proc.score = Math.max(proc.score, event.score || 0);
        proc.lastSeen = Date.now();
        proc.comm = event.comm;

        if (event.killed) {
            proc.status = 'killed';
        } else if (event.score > 0.3) {
            proc.status = 'suspicious';
        }

        // Track honeyfile hits
        if (event.flags & 1) {
            state.stats.honeyfileHits++;
        }

        // Track kills
        if (event.killed || (event.flags & 16)) {
            state.stats.processesKilled++;
        }

        // Update max score
        if (event.score > state.maxScore) {
            state.maxScore = event.score;
        }

        // Add to timeline
        addTimelineEntry(event);

        // Update DOM
        updateStats();
        updateProcessTable();
        updateGauge(state.maxScore);
        updateThreatLevel();
    }

    function handleAlert(alert) {
        state.alerts.push(alert);
        state.stats.alertsGenerated++;

        // Show toast for HIGH and CRITICAL
        if (alert.severity === 'high' || alert.severity === 'critical') {
            showToast(alert);
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // UI Update Functions
    // ════════════════════════════════════════════════════════════════════

    function updateStats() {
        els.statEvents.textContent = formatNumber(state.stats.eventsReceived);
        els.statAlerts.textContent = formatNumber(state.stats.alertsGenerated);
        els.statKilled.textContent = formatNumber(state.stats.processesKilled);
        els.statHoneyfiles.textContent = formatNumber(state.stats.honeyfileHits);
    }

    function updateThreatLevel() {
        let level = 'SAFE';
        let dataLevel = 'safe';

        if (state.maxScore >= 0.8) {
            level = 'CRITICAL';
            dataLevel = 'critical';
        } else if (state.maxScore >= 0.5) {
            level = 'ELEVATED';
            dataLevel = 'warning';
        } else if (state.maxScore >= 0.3) {
            level = 'WARNING';
            dataLevel = 'warning';
        }

        els.statThreat.textContent = level;
        els.threatCard.setAttribute('data-level', dataLevel);
    }

    function updateGauge(score) {
        const circumference = 534; // 2 * PI * 85
        const offset = circumference - (score * circumference);

        els.gaugeFill.style.strokeDashoffset = offset;
        els.gaugeValue.textContent = score.toFixed(2);

        // Color transition
        els.gaugeFill.classList.remove('warning', 'danger');
        if (score >= 0.6) {
            els.gaugeFill.classList.add('danger');
        } else if (score >= 0.3) {
            els.gaugeFill.classList.add('warning');
        }
    }

    function addTimelineEntry(event) {
        // Remove empty state
        if (els.timelineEmpty) {
            els.timelineEmpty.style.display = 'none';
        }

        // Check filter
        if (state.activeFilter !== 'all' && event.severity !== state.activeFilter) {
            return;
        }

        const entry = document.createElement('div');
        entry.className = 'event-entry';
        entry.setAttribute('data-severity', event.severity || 'info');

        const severityClass = event.severity || 'info';
        const time = new Date(event.timestamp).toLocaleTimeString();

        let badges = '';
        if (event.flags & 1) badges += '<span class="event-badge honeyfile">HONEYFILE</span>';
        if (event.flags & 16) badges += '<span class="event-badge killed">KILLED</span>';
        if (event.flags & 2) badges += '<span class="event-badge high-freq">HIGH-FREQ</span>';

        entry.innerHTML = `
            <div class="event-severity ${severityClass}"></div>
            <div class="event-content">
                <div class="event-header">
                    <span class="event-type">${event.event_type}${badges}</span>
                    <span class="event-time">${time}</span>
                </div>
                <div class="event-details">
                    <span class="event-pid">PID ${event.pid}</span>
                    <span> ${event.comm} → </span>
                    <span class="event-file">${truncatePath(event.filename, 50)}</span>
                </div>
            </div>
        `;

        // Prepend (newest first)
        els.timeline.insertBefore(entry, els.timeline.firstChild);

        // Limit timeline entries
        while (els.timeline.children.length > 100) {
            els.timeline.removeChild(els.timeline.lastChild);
        }
    }

    function updateProcessTable() {
        const rows = [];

        // Sort by score descending
        const sorted = [...state.processes.entries()]
            .sort((a, b) => b[1].score - a[1].score)
            .slice(0, 20); // Top 20

        for (const [pid, proc] of sorted) {
            const scoreColor = proc.score >= 0.6 ? 'var(--severity-critical)' :
                               proc.score >= 0.3 ? 'var(--severity-medium)' :
                               'var(--text-secondary)';

            rows.push(`
                <tr>
                    <td class="pid-cell">${pid}</td>
                    <td>${proc.comm}</td>
                    <td class="ops-cell">${proc.ops}</td>
                    <td class="score-cell" style="color: ${scoreColor}">${proc.score.toFixed(3)}</td>
                    <td><span class="process-status ${proc.status}">${proc.status.toUpperCase()}</span></td>
                </tr>
            `);
        }

        els.processTbody.innerHTML = rows.join('');
        els.processCount.textContent = state.processes.size;
    }

    // ════════════════════════════════════════════════════════════════════
    // Toast Notifications
    // ════════════════════════════════════════════════════════════════════

    function showToast(alert) {
        const toast = document.createElement('div');
        const toastClass = alert.severity === 'critical' ? 'critical' :
                           alert.severity === 'high' ? 'warning' : 'success';

        const icon = alert.severity === 'critical'
            ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>'
            : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';

        const title = alert.killed
            ? `🛡️ RANSOMWARE KILLED — PID ${alert.pid}`
            : `⚠️ ${alert.severity.toUpperCase()} — ${alert.trigger}`;

        const message = alert.killed
            ? `Process "${alert.comm}" terminated. Honeyfile accessed.`
            : `${alert.comm} (PID ${alert.pid}) — Score: ${alert.score.toFixed(3)}`;

        toast.className = `toast ${toastClass}`;
        toast.innerHTML = `
            <div class="toast-icon">${icon}</div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>
        `;

        els.toastContainer.appendChild(toast);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    // ════════════════════════════════════════════════════════════════════
    // Uptime Clock
    // ════════════════════════════════════════════════════════════════════

    function updateUptime() {
        const elapsed = Math.floor((Date.now() - state.startTime) / 1000);
        const h = Math.floor(elapsed / 3600).toString().padStart(2, '0');
        const m = Math.floor((elapsed % 3600) / 60).toString().padStart(2, '0');
        const s = (elapsed % 60).toString().padStart(2, '0');
        els.uptimeValue.textContent = `${h}:${m}:${s}`;
    }

    // ════════════════════════════════════════════════════════════════════
    // Frequency Chart Update (every 1 second)
    // ════════════════════════════════════════════════════════════════════

    function updateFrequencyChart() {
        chart.pushAll(
            freqAccum.open,
            freqAccum.write,
            freqAccum.rename,
            freqAccum.unlink
        );

        // Reset accumulators
        freqAccum.open = 0;
        freqAccum.write = 0;
        freqAccum.rename = 0;
        freqAccum.unlink = 0;
    }

    // ════════════════════════════════════════════════════════════════════
    // Utility Functions
    // ════════════════════════════════════════════════════════════════════

    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return n.toString();
    }

    function truncatePath(path, maxLen) {
        if (!path || path.length <= maxLen) return path;
        const parts = path.split('/');
        if (parts.length <= 2) return '...' + path.slice(-maxLen + 3);
        return '.../' + parts.slice(-2).join('/');
    }

    // ════════════════════════════════════════════════════════════════════
    // Event Bindings
    // ════════════════════════════════════════════════════════════════════

    // Simulate button
    els.btnSimulate.addEventListener('click', () => {
        if (!state.simulationActive) {
            state.simulationActive = true;
            els.btnSimulate.querySelector('span').textContent = 'Attack!';
            els.btnSimulate.style.borderColor = 'rgba(239, 68, 68, 0.5)';
            stream.triggerAttack();
        } else {
            state.simulationActive = false;
            els.btnSimulate.querySelector('span').textContent = 'Simulate';
            els.btnSimulate.style.borderColor = '';
            stream.resetToNormal();
        }
    });

    // Clear button
    els.btnClear.addEventListener('click', () => {
        state.events = [];
        state.alerts = [];
        state.processes.clear();
        state.stats = { eventsReceived: 0, alertsGenerated: 0, processesKilled: 0, honeyfileHits: 0 };
        state.maxScore = 0;

        els.timeline.innerHTML = '';
        if (els.timelineEmpty) {
            els.timelineEmpty.style.display = '';
            els.timeline.appendChild(els.timelineEmpty);
        }
        els.processTbody.innerHTML = '';

        updateStats();
        updateGauge(0);
        updateThreatLevel();
    });

    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.activeFilter = btn.dataset.filter;

            // Re-render timeline with filter
            els.timeline.innerHTML = '';
            const filtered = state.events.filter(e =>
                state.activeFilter === 'all' || e.severity === state.activeFilter
            ).slice(-50);

            if (filtered.length === 0 && els.timelineEmpty) {
                els.timelineEmpty.style.display = '';
                els.timeline.appendChild(els.timelineEmpty);
            } else {
                if (els.timelineEmpty) els.timelineEmpty.style.display = 'none';
                filtered.forEach(e => addTimelineEntry(e));
            }
        });
    });

    // ════════════════════════════════════════════════════════════════════
    // Start Everything
    // ════════════════════════════════════════════════════════════════════

    // Update uptime every second
    setInterval(updateUptime, 1000);

    // Update frequency chart every second
    setInterval(updateFrequencyChart, 1000);

    // Start the event stream
    stream.start();

    console.log('[K-Sentinel Dashboard] Initialized');
    console.log('[K-Sentinel Dashboard] Click "Simulate" to trigger a ransomware attack demo');

})();
