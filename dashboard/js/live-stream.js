/**
 * K-Sentinel Dashboard — Live Event Stream
 * live-stream.js
 *
 * Drop-in replacement for EventStream that consumes REAL agent events from
 * the bridge (scripts/dashboard_bridge.py) via Server-Sent Events.
 * Enabled by opening the dashboard with  ?live=1
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

class LiveEventStream {
    constructor(options = {}) {
        this.onEvent = options.onEvent || (() => {});
        this.onAlert = options.onAlert || (() => {});
        this.url = options.url || '/events';
        this.source = null;
        this.alertId = 0;
        this.eventCount = 0;
        this.running = false;
    }

    start() {
        if (this.running) return;
        this.running = true;
        this.source = new EventSource(this.url);
        this.source.onmessage = (msg) => {
            try {
                this._handle(JSON.parse(msg.data));
            } catch (e) {
                console.warn('[K-Sentinel] bad event', e);
            }
        };
        this.source.onerror = () => console.warn('[K-Sentinel] live stream reconnecting…');
        console.log('[K-Sentinel Dashboard] LIVE mode — streaming from ' + this.url);
    }

    stop() {
        this.running = false;
        if (this.source) { this.source.close(); this.source = null; }
    }

    // Live mode ignores the simulator controls.
    triggerAttack() {}
    resetToNormal() {}

    _type(t) {
        t = (t || '').toLowerCase();
        if (t.startsWith('open')) return 'OPEN';
        if (t.startsWith('write')) return 'WRITE';
        if (t.startsWith('rename')) return 'RENAME';
        if (t.startsWith('unlink')) return 'UNLINK';
        return t.toUpperCase();
    }

    _handle(a) {
        const e = a.event || {};
        const sev = (a.severity || 'info').toLowerCase();
        const event = {
            timestamp: a.timestamp,
            kernel_time_ns: a.kernel_time_ns,
            pid: e.pid, tgid: e.tgid, uid: e.uid, ppid: e.ppid,
            comm: e.comm,
            event_type: this._type(e.type),
            filename: e.filename,
            flags: e.flags || 0,
            write_size: e.write_size || 0,
            severity: sev,
            score: a.scores ? a.scores.total : 0,
            trigger: a.trigger,
            action: a.action_taken,
            killed: !!a.kill_success,
        };
        this.eventCount++;
        this.onEvent(event);
        if (event.flags > 0 || sev !== 'info') {
            this.onAlert({
                alert_id: ++this.alertId,
                timestamp: event.timestamp,
                severity: sev,
                trigger: event.trigger,
                action: event.action,
                pid: event.pid,
                comm: event.comm,
                filename: event.filename,
                score: event.score,
                killed: event.killed,
            });
        }
    }
}

window.LiveEventStream = LiveEventStream;
