/**
 * K-Sentinel Dashboard — Event Stream Module
 * event-stream.js
 *
 * Simulates a real-time event stream from the K-Sentinel agent.
 * In production, this would connect via Server-Sent Events (SSE)
 * or WebSocket to the agent's dashboard endpoint.
 *
 * For the demo/presentation, this generates realistic synthetic
 * events that showcase the detection engine's capabilities.
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

class EventStream {
    constructor(options = {}) {
        this.onEvent = options.onEvent || (() => {});
        this.onAlert = options.onAlert || (() => {});
        this.running = false;
        this.intervalId = null;
        this.alertId = 0;
        this.eventCount = 0;

        // Simulation parameters
        this.baseInterval = options.interval || 800; // ms between events
        this.mode = 'normal'; // 'normal' | 'attack' | 'honeypot'
        this.attackPhase = 0;

        // Process pool for realistic simulation
        this.normalProcesses = [
            { pid: 1042, comm: 'nginx',     uid: 33 },
            { pid: 2187, comm: 'postgres',  uid: 26 },
            { pid: 3456, comm: 'node',      uid: 1000 },
            { pid: 4521, comm: 'python3',   uid: 1000 },
            { pid: 5678, comm: 'sshd',      uid: 0 },
            { pid: 6234, comm: 'cron',      uid: 0 },
            { pid: 7890, comm: 'rsync',     uid: 1000 },
            { pid: 8112, comm: 'vim',       uid: 1000 },
        ];

        this.attackProcess = { pid: 31337, comm: 'cryptor.elf', uid: 1000 };

        this.normalFiles = [
            '/var/log/nginx/access.log',
            '/var/log/syslog',
            '/tmp/session_cache.dat',
            '/home/user/project/main.py',
            '/etc/nginx/nginx.conf',
            '/var/lib/postgresql/data/pg_wal',
            '/home/user/.bashrc',
            '/opt/app/config.json',
        ];

        this.attackFiles = [
            '/home/user/Documents/report_2026.docx',
            '/home/user/Documents/budget.xlsx',
            '/home/user/Photos/vacation_001.jpg',
            '/home/user/Projects/source_code.tar.gz',
            '/home/user/Desktop/passwords.csv',
            '/home/user/Documents/thesis_final.pdf',
        ];

        this.honeyfiles = [
            '/home/user/Documents/financial/Q4_Budget_Report_2026.xlsx',
            '/opt/backups/customer_db_backup.sql',
            '/home/user/.ssh_key_backup.pem',
        ];
    }

    /**
     * Start the event stream simulation.
     */
    start() {
        if (this.running) return;
        this.running = true;
        this._tick();
    }

    /**
     * Stop the event stream.
     */
    stop() {
        this.running = false;
        if (this.intervalId) {
            clearTimeout(this.intervalId);
            this.intervalId = null;
        }
    }

    /**
     * Trigger a simulated ransomware attack sequence.
     */
    triggerAttack() {
        this.mode = 'attack';
        this.attackPhase = 0;
    }

    /**
     * Reset to normal mode.
     */
    resetToNormal() {
        this.mode = 'normal';
        this.attackPhase = 0;
    }

    _tick() {
        if (!this.running) return;

        let event;
        let interval = this.baseInterval;

        switch (this.mode) {
            case 'normal':
                event = this._generateNormalEvent();
                interval = this.baseInterval + Math.random() * 500;
                break;

            case 'attack':
                event = this._generateAttackEvent();
                interval = 50 + Math.random() * 100; // Much faster during attack
                break;
        }

        if (event) {
            this.eventCount++;
            this.onEvent(event);

            // Generate alert for significant events
            if (event.flags > 0 || event.severity !== 'info') {
                this.onAlert(this._eventToAlert(event));
            }
        }

        this.intervalId = setTimeout(() => this._tick(), interval);
    }

    _generateNormalEvent() {
        const proc = this.normalProcesses[
            Math.floor(Math.random() * this.normalProcesses.length)
        ];
        const file = this.normalFiles[
            Math.floor(Math.random() * this.normalFiles.length)
        ];

        const types = ['OPEN', 'WRITE', 'OPEN', 'WRITE', 'OPEN', 'CLOSE'];
        const type = types[Math.floor(Math.random() * types.length)];

        return {
            timestamp: new Date().toISOString(),
            kernel_time_ns: Date.now() * 1000000,
            pid: proc.pid,
            tgid: proc.pid,
            uid: proc.uid,
            ppid: 1,
            comm: proc.comm,
            event_type: type,
            filename: file,
            flags: 0,
            write_size: type === 'WRITE' ? Math.floor(Math.random() * 8192) : 0,
            severity: 'info',
            score: Math.random() * 0.05,
            trigger: null,
            action: 'NONE',
        };
    }

    _generateAttackEvent() {
        this.attackPhase++;

        // Phase 1 (0-20): Reconnaissance — rapid file scanning
        if (this.attackPhase <= 20) {
            const file = this.attackFiles[
                Math.floor(Math.random() * this.attackFiles.length)
            ];
            return {
                timestamp: new Date().toISOString(),
                kernel_time_ns: Date.now() * 1000000,
                pid: this.attackProcess.pid,
                tgid: this.attackProcess.pid,
                uid: this.attackProcess.uid,
                ppid: 3456,
                comm: this.attackProcess.comm,
                event_type: 'OPEN',
                filename: file,
                flags: 0,
                write_size: 0,
                severity: this.attackPhase > 10 ? 'low' : 'info',
                score: 0.05 + (this.attackPhase * 0.015),
                trigger: this.attackPhase > 10 ? 'HIGH_FREQUENCY' : null,
                action: 'LOG',
            };
        }

        // Phase 2 (21-50): Encryption — rapid read/write cycles
        if (this.attackPhase <= 50) {
            const fileIdx = (this.attackPhase - 21) % this.attackFiles.length;
            const file = this.attackFiles[fileIdx];
            const isWrite = this.attackPhase % 2 === 0;

            const score = 0.3 + ((this.attackPhase - 20) * 0.02);
            let severity = 'medium';
            if (score > 0.6) severity = 'high';

            return {
                timestamp: new Date().toISOString(),
                kernel_time_ns: Date.now() * 1000000,
                pid: this.attackProcess.pid,
                tgid: this.attackProcess.pid,
                uid: this.attackProcess.uid,
                ppid: 3456,
                comm: this.attackProcess.comm,
                event_type: isWrite ? 'WRITE' : 'OPEN',
                filename: file,
                flags: 2, // HIGH_FREQ
                write_size: isWrite ? 4096 + Math.floor(Math.random() * 32768) : 0,
                severity: severity,
                score: Math.min(score, 0.85),
                trigger: 'HIGH_FREQUENCY',
                action: score > 0.6 ? 'ALERT' : 'LOG',
            };
        }

        // Phase 3 (51-65): Mass rename with encryption extensions
        if (this.attackPhase <= 65) {
            const fileIdx = (this.attackPhase - 51) % this.attackFiles.length;
            const file = this.attackFiles[fileIdx];
            const exts = ['.encrypted', '.locked', '.WNCRY'];
            const ext = exts[Math.floor(Math.random() * exts.length)];

            return {
                timestamp: new Date().toISOString(),
                kernel_time_ns: Date.now() * 1000000,
                pid: this.attackProcess.pid,
                tgid: this.attackProcess.pid,
                uid: this.attackProcess.uid,
                ppid: 3456,
                comm: this.attackProcess.comm,
                event_type: 'RENAME',
                filename: `${file} → ${file}${ext}`,
                flags: 2, // HIGH_FREQ
                write_size: 0,
                severity: 'high',
                score: 0.75 + Math.random() * 0.1,
                trigger: 'MASS_RENAME',
                action: 'SIGKILL',
            };
        }

        // Phase 4 (66): Honeyfile access — CAUGHT!
        if (this.attackPhase === 66) {
            const honeyfile = this.honeyfiles[0];

            return {
                timestamp: new Date().toISOString(),
                kernel_time_ns: Date.now() * 1000000,
                pid: this.attackProcess.pid,
                tgid: this.attackProcess.pid,
                uid: this.attackProcess.uid,
                ppid: 3456,
                comm: this.attackProcess.comm,
                event_type: 'OPEN',
                filename: honeyfile,
                flags: 1 | 16, // HONEYFILE | KILLED
                write_size: 0,
                severity: 'critical',
                score: 1.0,
                trigger: 'HONEYFILE_ACCESS',
                action: 'SIGKILL',
                killed: true,
            };
        }

        // After attack — return to normal
        this.mode = 'normal';
        return this._generateNormalEvent();
    }

    _eventToAlert(event) {
        return {
            alert_id: ++this.alertId,
            timestamp: event.timestamp,
            severity: event.severity,
            trigger: event.trigger,
            action: event.action,
            pid: event.pid,
            comm: event.comm,
            filename: event.filename,
            score: event.score,
            killed: event.killed || false,
        };
    }
}

// Export
window.EventStream = EventStream;
