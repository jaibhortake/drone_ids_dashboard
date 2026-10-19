'use strict';

/** Chart.js and Leaflet widgets. */
const Charts = (() => {
    const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const ATTITUDE_POINTS = 120;

    Chart.defaults.color = css('--muted');
    Chart.defaults.borderColor = 'rgba(148, 163, 184, 0.12)';
    Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;

    const levelChart = new Chart(document.getElementById('levelChart'), {
        type: 'doughnut',
        data: {
            labels: LEVELS.map((l) => l[0] + l.slice(1).toLowerCase()),
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: LEVELS.map((l) => css(`--${l.toLowerCase()}`)),
                borderColor: css('--bg-2'),
                borderWidth: 3,
            }],
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '68%',
            plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, padding: 16 } } },
        },
    });

    const attitudeChart = new Chart(document.getElementById('attitudeChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'Roll', data: [], borderColor: css('--accent'), tension: 0.3, pointRadius: 0, borderWidth: 2 },
                { label: 'Pitch', data: [], borderColor: css('--accent-2'), tension: 0.3, pointRadius: 0, borderWidth: 2 },
            ],
        },
        options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            scales: { x: { display: false }, y: { suggestedMin: -45, suggestedMax: 45 } },
            plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } },
        },
    });

    function updateLevels(threatLevels) {
        levelChart.data.datasets[0].data = LEVELS.map((l) => threatLevels?.[l] || 0);
        levelChart.update();
    }

    function pushAttitude({ roll, pitch }) {
        const d = attitudeChart.data;
        d.labels.push('');
        d.datasets[0].data.push(roll);
        d.datasets[1].data.push(pitch);
        if (d.labels.length > ATTITUDE_POINTS) {
            d.labels.shift();
            d.datasets.forEach((ds) => ds.data.shift());
        }
        attitudeChart.update('none');
    }

    // ---- map ----
    const TRACK_POINTS = 600;
    const map = L.map('map', { zoomControl: true, attributionControl: true }).setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap contributors',
    }).addTo(map);
    const track = L.polyline([], { color: css('--accent'), weight: 3 }).addTo(map);
    const marker = L.circleMarker([0, 0], {
        radius: 7, color: '#fff', weight: 2, fillColor: css('--accent'), fillOpacity: 1,
    });
    let centered = false;

    function pushPosition({ lat, lon }) {
        const pts = track.getLatLngs();
        pts.push([lat, lon]);
        if (pts.length > TRACK_POINTS) pts.shift();
        track.setLatLngs(pts);
        marker.setLatLng([lat, lon]);
        if (!map.hasLayer(marker)) marker.addTo(map);
        if (!centered) { map.setView([lat, lon], 17); centered = true; }
    }

    return { updateLevels, pushAttitude, pushPosition, invalidate: () => map.invalidateSize() };
})();
