/**
 * K-Sentinel Dashboard — Charts Module
 * charts.js
 *
 * Custom canvas-based chart renderer for the syscall frequency
 * visualization. No external charting library required.
 *
 * Copyright (c) 2026 K-Sentinel Project
 * SPDX-License-Identifier: MIT
 */

class FrequencyChart {
    constructor(canvasId, options = {}) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');

        // Chart configuration
        this.maxDataPoints = options.maxDataPoints || 60;
        this.gridColor = options.gridColor || 'rgba(255, 255, 255, 0.04)';
        this.axisColor = options.axisColor || 'rgba(255, 255, 255, 0.1)';
        this.textColor = options.textColor || 'rgba(148, 163, 184, 0.8)';
        this.animationSpeed = options.animationSpeed || 0.08;

        // Data series
        this.series = {
            open:   { data: [], color: '#3b82f6', label: 'openat',     current: 0, target: 0 },
            write:  { data: [], color: '#06b6d4', label: 'write',      current: 0, target: 0 },
            rename: { data: [], color: '#f59e0b', label: 'renameat2',  current: 0, target: 0 },
            unlink: { data: [], color: '#ef4444', label: 'unlinkat',   current: 0, target: 0 },
        };

        // Initialize data arrays
        for (const key in this.series) {
            this.series[key].data = new Array(this.maxDataPoints).fill(0);
        }

        // Padding and layout
        this.padding = { top: 20, right: 20, bottom: 35, left: 45 };

        // Animation state
        this.animating = false;
        this.maxY = 10; // Initial max Y value
        this.targetMaxY = 10;

        this._setupCanvas();
        this._startAnimation();
    }

    _setupCanvas() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;

        this.canvas.width = rect.width * dpr;
        this.canvas.height = rect.height * dpr;
        this.canvas.style.width = `${rect.width}px`;
        this.canvas.style.height = `${rect.height}px`;

        this.ctx.scale(dpr, dpr);
        this.width = rect.width;
        this.height = rect.height;

        // Handle resize
        this._resizeObserver = new ResizeObserver(() => {
            const r = this.canvas.parentElement.getBoundingClientRect();
            const d = window.devicePixelRatio || 1;
            this.canvas.width = r.width * d;
            this.canvas.height = r.height * d;
            this.canvas.style.width = `${r.width}px`;
            this.canvas.style.height = `${r.height}px`;
            this.ctx.setTransform(1, 0, 0, 1, 0, 0);
            this.ctx.scale(d, d);
            this.width = r.width;
            this.height = r.height;
        });
        this._resizeObserver.observe(this.canvas.parentElement);
    }

    /**
     * Push new data point for a series.
     * @param {string} type - 'open', 'write', 'rename', 'unlink'
     * @param {number} value - The count for this tick
     */
    pushData(type, value) {
        const s = this.series[type];
        if (!s) return;

        s.data.push(value);
        if (s.data.length > this.maxDataPoints) {
            s.data.shift();
        }

        // Update target max Y
        const allMax = Math.max(
            ...Object.values(this.series).map(
                ser => Math.max(...ser.data, 1)
            )
        );
        this.targetMaxY = Math.ceil(allMax * 1.2);
        if (this.targetMaxY < 10) this.targetMaxY = 10;
    }

    /**
     * Push data for all series at once.
     */
    pushAll(open, write, rename, unlink) {
        this.pushData('open', open);
        this.pushData('write', write);
        this.pushData('rename', rename);
        this.pushData('unlink', unlink);
    }

    _startAnimation() {
        const animate = () => {
            this._animate();
            this._draw();
            requestAnimationFrame(animate);
        };
        requestAnimationFrame(animate);
    }

    _animate() {
        // Smooth maxY transition
        this.maxY += (this.targetMaxY - this.maxY) * this.animationSpeed;
    }

    _draw() {
        const { ctx, width, height, padding } = this;
        const chartW = width - padding.left - padding.right;
        const chartH = height - padding.top - padding.bottom;

        // Clear
        ctx.clearRect(0, 0, width, height);

        // Draw grid
        this._drawGrid(chartW, chartH);

        // Draw each series
        for (const key in this.series) {
            this._drawSeries(this.series[key], chartW, chartH);
        }

        // Draw legend
        this._drawLegend(chartW);
    }

    _drawGrid(chartW, chartH) {
        const { ctx, padding, maxY, textColor, gridColor, axisColor } = this;
        const numHLines = 5;
        const numVLines = 6;

        ctx.save();
        ctx.translate(padding.left, padding.top);

        // Horizontal grid lines + Y labels
        ctx.font = '10px "JetBrains Mono", monospace';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';

        for (let i = 0; i <= numHLines; i++) {
            const y = chartH - (i / numHLines) * chartH;
            const val = Math.round((i / numHLines) * maxY);

            // Grid line
            ctx.strokeStyle = gridColor;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(chartW, y);
            ctx.stroke();

            // Label
            ctx.fillStyle = textColor;
            ctx.fillText(val.toString(), -8, y);
        }

        // Vertical guide lines
        for (let i = 0; i <= numVLines; i++) {
            const x = (i / numVLines) * chartW;
            ctx.strokeStyle = gridColor;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, chartH);
            ctx.stroke();
        }

        // Axes
        ctx.strokeStyle = axisColor;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, chartH);
        ctx.lineTo(chartW, chartH);
        ctx.stroke();

        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.lineTo(0, chartH);
        ctx.stroke();

        // X-axis label
        ctx.fillStyle = textColor;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText('Time (seconds ago)', chartW / 2, chartH + 18);

        // Y-axis label (rotated)
        ctx.save();
        ctx.translate(-32, chartH / 2);
        ctx.rotate(-Math.PI / 2);
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('Ops/sec', 0, 0);
        ctx.restore();

        ctx.restore();
    }

    _drawSeries(series, chartW, chartH) {
        const { ctx, padding, maxY, maxDataPoints } = this;
        const { data, color } = series;

        if (data.length < 2) return;

        ctx.save();
        ctx.translate(padding.left, padding.top);

        const stepX = chartW / (maxDataPoints - 1);

        // Draw filled area
        ctx.beginPath();
        ctx.moveTo(0, chartH);

        for (let i = 0; i < data.length; i++) {
            const x = i * stepX;
            const y = chartH - (data[i] / maxY) * chartH;
            if (i === 0) {
                ctx.lineTo(x, y);
            } else {
                // Smooth curve
                const prevX = (i - 1) * stepX;
                const prevY = chartH - (data[i - 1] / maxY) * chartH;
                const cpX = (prevX + x) / 2;
                ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
            }
        }

        ctx.lineTo((data.length - 1) * stepX, chartH);
        ctx.closePath();

        // Gradient fill
        const gradient = ctx.createLinearGradient(0, 0, 0, chartH);
        gradient.addColorStop(0, color + '20');
        gradient.addColorStop(1, color + '02');
        ctx.fillStyle = gradient;
        ctx.fill();

        // Draw line
        ctx.beginPath();
        for (let i = 0; i < data.length; i++) {
            const x = i * stepX;
            const y = chartH - (data[i] / maxY) * chartH;
            if (i === 0) {
                ctx.moveTo(x, y);
            } else {
                const prevX = (i - 1) * stepX;
                const prevY = chartH - (data[i - 1] / maxY) * chartH;
                const cpX = (prevX + x) / 2;
                ctx.bezierCurveTo(cpX, prevY, cpX, y, x, y);
            }
        }

        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();

        // Draw end dot
        if (data.length > 0) {
            const lastX = (data.length - 1) * stepX;
            const lastY = chartH - (data[data.length - 1] / maxY) * chartH;

            ctx.beginPath();
            ctx.arc(lastX, lastY, 3, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();

            // Glow
            ctx.beginPath();
            ctx.arc(lastX, lastY, 6, 0, Math.PI * 2);
            ctx.fillStyle = color + '30';
            ctx.fill();
        }

        ctx.restore();
    }

    _drawLegend(chartW) {
        const { ctx, padding, height } = this;
        const keys = Object.keys(this.series);
        const totalWidth = keys.length * 100;
        let startX = padding.left + (chartW - totalWidth) / 2;

        ctx.save();
        ctx.font = '10px "JetBrains Mono", monospace';
        ctx.textBaseline = 'middle';

        for (const key of keys) {
            const s = this.series[key];

            // Color dot
            ctx.fillStyle = s.color;
            ctx.beginPath();
            ctx.arc(startX, height - 8, 4, 0, Math.PI * 2);
            ctx.fill();

            // Label
            ctx.fillStyle = this.textColor;
            ctx.textAlign = 'left';
            ctx.fillText(s.label, startX + 10, height - 8);

            startX += 100;
        }

        ctx.restore();
    }

    destroy() {
        if (this._resizeObserver) {
            this._resizeObserver.disconnect();
        }
    }
}

// Export for use in app.js
window.FrequencyChart = FrequencyChart;
