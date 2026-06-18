/* ============================================================
   NetWatch Portal — helpers UI « live »
   Compteurs animés, sparklines (Chart.js), horloge relative,
   toasts, surlignage des nouvelles lignes. Vanilla + Chart.js.
   ============================================================ */
(function () {
  "use strict";

  const NW = {};
  const prefersReduced = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const ACCENT = "#22d3ee";
  const CRIT   = "#ff4d5e";

  /* ---- Compteur animé -------------------------------------- */
  NW.countUp = function (el, to, duration) {
    to = Number(to) || 0;
    if (prefersReduced || to === 0) { el.textContent = to.toLocaleString("fr-FR"); return; }
    duration = duration || 900;
    const start = performance.now();
    const from = 0;
    function tick(now) {
      const p = Math.min((now - start) / duration, 1);
      // easeOutCubic
      const v = Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3)));
      el.textContent = v.toLocaleString("fr-FR");
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  };

  /* Anime tous les [data-countup] présents au chargement */
  NW.autoCountUp = function (root) {
    (root || document).querySelectorAll("[data-countup]").forEach(function (el) {
      const target = parseFloat(el.getAttribute("data-countup"));
      if (!isNaN(target)) NW.countUp(el, target);
    });
  };

  /* ---- Sparkline (Chart.js) -------------------------------- */
  NW.sparkline = function (canvas, points, opts) {
    if (typeof Chart === "undefined" || !canvas) return null;
    opts = opts || {};
    const color = opts.color || ACCENT;
    // Détruit l'instance précédente (re-render au refresh)
    if (canvas._nwChart) { canvas._nwChart.destroy(); canvas._nwChart = null; }
    const ctx = canvas.getContext("2d");
    const grad = ctx.createLinearGradient(0, 0, 0, canvas.height || 48);
    grad.addColorStop(0, color + "55");
    grad.addColorStop(1, color + "00");
    const chart = new Chart(ctx, {
      type: "line",
      data: {
        labels: points.map(function (_, i) { return i; }),
        datasets: [{
          data: points,
          borderColor: color,
          backgroundColor: grad,
          borderWidth: 1.6,
          fill: true,
          tension: 0.38,
          pointRadius: 0,
          pointHoverRadius: 3,
          pointHoverBackgroundColor: color,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: prefersReduced ? false : { duration: 600 },
        plugins: { legend: { display: false }, tooltip: opts.tooltip === false ? { enabled: false } : {
          displayColors: false,
          backgroundColor: "#0b1019",
          borderColor: "#1e2a3c",
          borderWidth: 1,
          padding: 8,
          callbacks: { title: function () { return ""; },
            label: function (c) { return c.parsed.y + " alerte(s)"; } },
        } },
        scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
      },
    });
    canvas._nwChart = chart;
    return chart;
  };

  /* Charge /api/alerts/series et rend les sparklines déclarées
     via [data-sparkline="total|critical"] (canvas). */
  NW.loadAlertSparklines = function () {
    const nodes = document.querySelectorAll("[data-sparkline]");
    if (!nodes.length) return;
    fetch("/api/alerts/series")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (series) {
        if (!Array.isArray(series) || !series.length) {
          nodes.forEach(function (n) {
            const ph = n.closest("[data-spark-wrap]");
            if (ph) ph.style.display = "none";
          });
          return;
        }
        nodes.forEach(function (canvas) {
          const key = canvas.getAttribute("data-sparkline");
          const pts = series.map(function (b) { return b[key] || 0; });
          NW.sparkline(canvas, pts, { color: key === "critical" ? CRIT : ACCENT });
        });
      })
      .catch(function () {});
  };

  /* ---- Horloge relative « il y a Xs » ---------------------- */
  NW.relativeClocks = [];
  NW.registerClock = function (el) {
    const c = { el: el, ts: Date.now() };
    NW.relativeClocks.push(c);
    return c;
  };
  function tickClocks() {
    const now = Date.now();
    NW.relativeClocks.forEach(function (c) {
      const s = Math.round((now - c.ts) / 1000);
      const label = s < 2 ? "à l'instant" : "il y a " + s + " s";
      const span = c.el.querySelector(".rel-time");
      if (span) span.textContent = label;
    });
  }
  setInterval(tickClocks, 1000);

  /* ---- Toasts --------------------------------------------- */
  NW.toast = function (message, category) {
    const host = document.getElementById("toast-host");
    if (!host || typeof bootstrap === "undefined") return;
    const map = { success: "bi-check-circle-fill", danger: "bi-x-circle-fill",
                  warning: "bi-exclamation-triangle-fill", info: "bi-info-circle-fill" };
    const el = document.createElement("div");
    el.className = "toast nw-toast nw-toast-" + (category || "info");
    el.setAttribute("role", "alert");
    // Structure statique en innerHTML ; le message (potentiellement issu de
    // données utilisateur) est inséré via textContent → pas d'injection HTML.
    el.innerHTML =
      '<div class="toast-body d-flex align-items-center gap-2">' +
      '<i class="bi ' + (map[category] || map.info) + '"></i>' +
      '<span class="flex-grow-1"></span>' +
      '<button type="button" class="btn-close btn-close-sm" data-bs-dismiss="toast"></button>' +
      '</div>';
    el.querySelector(".flex-grow-1").textContent = message;
    host.appendChild(el);
    const t = new bootstrap.Toast(el, { delay: 5000 });
    t.show();
    el.addEventListener("hidden.bs.toast", function () { el.remove(); });
  };

  /* Convertit les messages flash injectés (data-flash) en toasts */
  NW.flushFlashes = function () {
    document.querySelectorAll("#flash-data > [data-flash]").forEach(function (n) {
      NW.toast(n.getAttribute("data-message"), n.getAttribute("data-flash"));
    });
  };

  document.addEventListener("DOMContentLoaded", function () {
    NW.autoCountUp();
    NW.loadAlertSparklines();
    NW.flushFlashes();
  });

  window.NW = NW;
})();
