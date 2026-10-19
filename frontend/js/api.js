'use strict';

/** Token storage + authenticated REST calls. Token lives in sessionStorage (cleared when the tab closes). */
const Api = (() => {
    const KEY = 'ids-token';

    function storage() {
        try { return window.sessionStorage; } catch { return null; }
    }

    function getToken() {
        // Accept a one-time #token=... link from the server log, then strip it from the URL.
        const match = location.hash.match(/token=([^&]+)/);
        if (match) {
            setToken(decodeURIComponent(match[1]));
            history.replaceState(null, '', location.pathname + location.search);
        }
        return storage()?.getItem(KEY) || null;
    }

    function setToken(token) { storage()?.setItem(KEY, token); }
    function clearToken() { storage()?.removeItem(KEY); }

    class UnauthorizedError extends Error {}

    async function request(path, { method = 'GET', body } = {}) {
        const headers = { Authorization: `Bearer ${getToken() || ''}` };
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
        if (res.status === 401) throw new UnauthorizedError('unauthorized');
        const data = res.headers.get('content-type')?.includes('json') ? await res.json() : await res.text();
        if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
        return data;
    }

    async function download(format) {
        const res = await fetch(`/api/alerts/export?format=${encodeURIComponent(format)}`, {
            headers: { Authorization: `Bearer ${getToken() || ''}` },
        });
        if (res.status === 401) throw new UnauthorizedError('unauthorized');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const url = URL.createObjectURL(await res.blob());
        const a = Object.assign(document.createElement('a'), { href: url, download: `alerts.${format}` });
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }

    return {
        getToken, setToken, clearToken, UnauthorizedError, download,
        status: () => request('/api/status'),
        scenarios: () => request('/api/scenarios'),
        alerts: (minLevel, limit = 100) =>
            request(`/api/alerts?limit=${limit}${minLevel ? `&min_level=${minLevel}` : ''}`),
        ack: (id) => request(`/api/alerts/${id}/ack`, { method: 'POST' }),
        runTest: (testType) => request('/api/test', { method: 'POST', body: { test_type: testType } }),
    };
})();
