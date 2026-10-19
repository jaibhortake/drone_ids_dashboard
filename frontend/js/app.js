'use strict';

/** Dashboard wiring. All server data is rendered with textContent — never innerHTML. */
(() => {
    const $ = (id) => document.getElementById(id);
    const LEVEL_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    const MAX_ALERTS = 200;

    const state = { minLevel: '', hideAcked: false, sound: false, alerts: new Map(), socket: null };

    // ---------- toasts ----------
    function toast(message, kind = '') {
        const el = document.createElement('div');
        el.className = `toast ${kind}`;
        el.textContent = message;
        $('toasts').appendChild(el);
        setTimeout(() => el.remove(), 5000);
    }

    // ---------- auth ----------
    function showAuth(error = false) {
        $('authOverlay').hidden = false;
        $('authError').hidden = !error;
        $('tokenInput').focus();
    }

    $('authForm').addEventListener('submit', (e) => {
        e.preventDefault();
        Api.setToken($('tokenInput').value.trim());
        $('tokenInput').value = '';
        start();
    });

    $('logoutBtn').addEventListener('click', () => {
        Api.clearToken();
        state.socket?.disconnect();
        showAuth();
    });

    async function guarded(fn) {
        try {
            return await fn();
        } catch (err) {
            if (err instanceof Api.UnauthorizedError) {
                Api.clearToken();
                showAuth(true);
            } else {
                toast(err.message, 'error');
            }
        }
    }

    // ---------- status ----------
    function setPill(pill, text, on, bad = false) {
        pill.classList.toggle('on', on);
        pill.classList.toggle('bad', bad);
        pill.querySelector('span:last-child').textContent = text;
    }

    function renderStatus(status) {
        $('kpiTotal').textContent = status.total_alerts ?? 0;
        $('kpiCritical').textContent = status.threat_levels?.CRITICAL ?? 0;
        $('kpiUnacked').textContent = status.unacknowledged ?? 0;
        if (status.flight_mode) $('kpiMode').textContent = status.flight_mode;
        Charts.updateLevels(status.threat_levels);
        renderAttackTypes(status.attack_types || {});
    }

    function renderAttackTypes(types) {
        const list = $('attackTypes');
        const entries = Object.entries(types).sort((a, b) => b[1] - a[1]);
        list.replaceChildren();
        if (!entries.length) {
            const li = document.createElement('li');
            li.className = 'muted';
            li.textContent = 'No attacks detected';
            list.appendChild(li);
            return;
        }
        const max = entries[0][1];
        for (const [name, count] of entries) {
            const li = document.createElement('li');
            li.className = 'bar-row';
            const label = document.createElement('div');
            label.className = 'bar-label';
            const n = document.createElement('span');
            n.textContent = name;
            const c = document.createElement('strong');
            c.textContent = count;
            label.append(n, c);
            const track = document.createElement('div');
            track.className = 'bar-track';
            const fill = document.createElement('div');
            fill.className = 'bar-fill';
            fill.style.width = `${(count / max) * 100}%`;
            track.appendChild(fill);
            li.append(label, track);
            list.appendChild(li);
        }
    }

    function setMonitoring(running) {
        setPill($('monitorPill'), running ? 'Monitoring' : 'Idle', running);
        $('startBtn').disabled = running;
        $('stopBtn').disabled = !running;
        $('connectionString').disabled = running;
    }

    // ---------- alerts ----------
    function visible(alert) {
        if (state.minLevel && LEVEL_RANK[alert.threat_level] < LEVEL_RANK[state.minLevel]) return false;
        return !(state.hideAcked && alert.acknowledged);
    }

    function alertNode(alert) {
        const node = $('alertTemplate').content.firstElementChild.cloneNode(true);
        node.dataset.level = alert.threat_level;
        node.dataset.id = alert.id;
        node.classList.toggle('acked', alert.acknowledged);
        node.querySelector('.sev').title = alert.threat_level;
        node.querySelector('.alert-type').textContent = `${alert.attack_type} · ${alert.threat_level}`;
        node.querySelector('.alert-source').textContent = alert.source;
        const time = node.querySelector('.alert-time');
        time.dateTime = alert.timestamp;
        time.textContent = new Date(alert.timestamp).toLocaleTimeString();
        node.querySelector('.alert-desc').textContent = alert.description;
        node.querySelector('.alert-action').textContent = alert.recommended_action;
        const ack = node.querySelector('.ack-btn');
        ack.hidden = alert.acknowledged || alert.id == null;
        ack.addEventListener('click', () => guarded(async () => {
            await Api.ack(alert.id);
            alert.acknowledged = true;
            renderAlerts();
        }));
        return node;
    }

    function renderAlerts() {
        const list = $('alertList');
        const items = [...state.alerts.values()].sort((a, b) => b.id - a.id).filter(visible);
        list.replaceChildren(...items.map(alertNode));
        $('alertEmpty').hidden = items.length > 0;
    }

    function addAlert(alert) {
        state.alerts.set(alert.id, alert);
        if (state.alerts.size > MAX_ALERTS) {
            state.alerts.delete(Math.min(...state.alerts.keys()));
        }
        renderAlerts();
        if (alert.threat_level === 'CRITICAL') {
            beep();
            toast(`${alert.attack_type}: ${alert.description}`, 'error');
        }
    }

    async function loadAlerts() {
        const alerts = await Api.alerts('', MAX_ALERTS);
        state.alerts = new Map(alerts.map((a) => [a.id, a]));
        renderAlerts();
    }

    document.querySelectorAll('.chip[data-level]').forEach((chip) => chip.addEventListener('click', () => {
        document.querySelectorAll('.chip[data-level]').forEach((c) => c.classList.toggle('active', c === chip));
        state.minLevel = chip.dataset.level;
        renderAlerts();
    }));
    $('hideAcked').addEventListener('change', (e) => { state.hideAcked = e.target.checked; renderAlerts(); });

    // ---------- sound ----------
    let audioCtx = null;
    function beep() {
        if (!state.sound) return;
        audioCtx ??= new AudioContext();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'square';
        osc.frequency.value = 880;
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.4);
        osc.connect(gain).connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.4);
    }
    $('soundBtn').addEventListener('click', (e) => {
        state.sound = !state.sound;
        e.currentTarget.textContent = state.sound ? '🔔' : '🔕';
        e.currentTarget.setAttribute('aria-pressed', String(state.sound));
        if (state.sound) beep();
    });

    // ---------- controls ----------
    $('startBtn').addEventListener('click', () => {
        const conn = $('connectionString').value.trim();
        if (!conn) return toast('Enter a connection string', 'error');
        state.socket?.emit('start_monitoring', { connection_string: conn });
    });
    $('stopBtn').addEventListener('click', () => state.socket?.emit('stop_monitoring'));

    $('testBtn').addEventListener('click', () => guarded(async () => {
        $('testBtn').disabled = true;
        try {
            const res = await Api.runTest($('scenarioSelect').value);
            toast(`Scenario "${res.test_type}" raised ${res.alerts_raised} alert(s)`, 'success');
        } finally {
            $('testBtn').disabled = false;
        }
    }));

    document.querySelectorAll('[data-export]').forEach((btn) => btn.addEventListener('click',
        () => guarded(() => Api.download(btn.dataset.export))));

    async function loadScenarios() {
        const select = $('scenarioSelect');
        const names = await Api.scenarios();
        select.replaceChildren(new Option('All scenarios', 'all'), ...names.map((n) => new Option(n.replace(/_/g, ' '), n)));
    }

    // ---------- socket ----------
    function connectSocket() {
        state.socket?.disconnect();
        const socket = io({ auth: { token: Api.getToken() } });
        state.socket = socket;

        socket.on('connect', () => setPill($('serverPill'), 'Connected', true));
        socket.on('disconnect', () => setPill($('serverPill'), 'Offline', false, true));
        socket.on('connect_error', () => {
            setPill($('serverPill'), 'Offline', false, true);
            // Server rejection (bad token) disables auto-reconnect; network errors keep retrying silently.
            if (!socket.active) guarded(Api.status);
        });
        socket.on('status', (d) => toast(d.message));
        socket.on('monitor_error', (d) => toast(d.message, 'error'));
        socket.on('monitor_state', (d) => setMonitoring(d.running));
        socket.on('status_update', renderStatus);
        socket.on('new_alert', addAlert);
        socket.on('vehicle', (d) => { $('kpiMode').textContent = d.mode; });
        socket.on('attitude', Charts.pushAttitude);
        socket.on('position', (p) => {
            Charts.pushPosition(p);
            $('posText').textContent = `${p.lat.toFixed(6)}, ${p.lon.toFixed(6)} · ${p.alt.toFixed(1)} m`;
        });
    }

    // ---------- boot ----------
    async function start() {
        if (!Api.getToken()) return showAuth();
        const ok = await guarded(async () => {
            renderStatus(await Api.status());
            await Promise.all([loadAlerts(), loadScenarios()]);
            return true;
        });
        if (!ok) return;
        $('authOverlay').hidden = true;
        connectSocket();
        Charts.invalidate();
    }

    start();
})();
