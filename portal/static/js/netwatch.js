/* ============================================================
   NetWatch Portal — helpers UI « live »
   Compteurs animés, sparklines (Chart.js), horloge relative,
   toasts, surlignage des nouvelles lignes. Vanilla + Chart.js.
   ============================================================ */
(function () {
  "use strict";

  const NW = {};

  /* ---- i18n ------------------------------------------------- */
  const TRANSLATIONS = {
    fr: {
      "ts_format":         "fr",
      "just_now":          "à l'instant",
      "ago":               "il y a {n} s",
      "alerts_label":      "{n} alertes",
      "alerts_in_header":  "alertes",
      /* Tableau alertes */
      "col_timestamp":     "Horodatage",
      "col_engine":        "Moteur",
      "col_severity":      "Sév.",
      "col_signature":     "Signature",
      "col_source":        "Source",
      "col_destination":   "Destination",
      /* Stats */
      "stat_total":        "Total alertes",
      "stat_24h":          "Dernières 24h",
      "stat_critical":     "Critiques (sev 1)",
      "stat_medium":       "Moyennes (sev 2)",
      /* Spark */
      "spark_label":       "Activité des alertes · 24 h",
      "spark_volume":      "Volume",
      "spark_critical":    "Critiques",
      /* Filtres */
      "filter_all":        "Tous",
      "filter_all_sev":    "Toutes sév.",
      "filter_search":     "Rechercher",
      /* Sévérités */
      "sev_critical":      "Critique",
      "sev_medium":        "Moyen",
      "sev_low":           "Faible",
      /* Tooltip sparkline */
      "spark_tooltip":     "alerte(s)",
      /* Modal IA */
      "modal_title":       "Assistant IA — explication de l'alerte",
      "modal_close":       "Fermer",
      "modal_privacy":     "Modèle exécuté localement (Ollama) — aucune donnée envoyée à l'extérieur",
      "modal_loading":     "L'assistant IA analyse l'alerte…",
      /* MITRE */
      "mitre_header":      "Top MITRE ATT&CK tactics",
      /* Empty states */
      "empty_es":          "Elasticsearch non joignable — lancez le stack NetWatch (<code>make start</code>)",
      "empty_filter":      "Aucune alerte pour ces filtres",
      "empty_no_data":     "Aucune alerte — stack silencieuse ou Elasticsearch vide (<code>make sim</code> pour générer du trafic)",
    },
    en: {
      "ts_format":         "en",
      "just_now":          "just now",
      "ago":               "{n}s ago",
      "alerts_label":      "{n} alerts",
      "alerts_in_header":  "alerts",
      "col_timestamp":     "Timestamp",
      "col_engine":        "Engine",
      "col_severity":      "Sev.",
      "col_signature":     "Signature",
      "col_source":        "Source",
      "col_destination":   "Destination",
      "stat_total":        "Total alerts",
      "stat_24h":          "Last 24h",
      "stat_critical":     "Critical (sev 1)",
      "stat_medium":       "Medium (sev 2)",
      "spark_label":       "Alert activity · 24h",
      "spark_volume":      "Volume",
      "spark_critical":    "Critical",
      "filter_all":        "All",
      "filter_all_sev":    "All sev.",
      "filter_search":     "Search",
      "sev_critical":      "Critical",
      "sev_medium":        "Medium",
      "sev_low":           "Low",
      "spark_tooltip":     "alert(s)",
      "modal_title":       "AI Assistant — alert explanation",
      "modal_close":       "Close",
      "modal_privacy":     "Model running locally (Ollama) — no data sent externally",
      "modal_loading":     "AI assistant is analysing the alert…",
      "mitre_header":      "Top MITRE ATT&CK tactics",
      "empty_es":          "Elasticsearch unreachable — start the NetWatch stack (<code>make start</code>)",
      "empty_filter":      "No alerts match the current filters",
      "empty_no_data":     "No alerts — stack silent or Elasticsearch empty (<code>make sim</code> to generate traffic)",
    },
  };

  NW.lang = localStorage.getItem("nw_lang") || "fr";

  NW.t = function (key, vars) {
    const dict = TRANSLATIONS[NW.lang] || TRANSLATIONS["fr"];
    let s = dict[key] || key;
    if (vars) Object.keys(vars).forEach(function (k) { s = s.replace("{" + k + "}", vars[k]); });
    return s;
  };

  /* Formate un timestamp ISO en DD/MM/YYYY HH:mm:ss (FR) ou YYYY-MM-DD HH:mm:ss (EN) */
  NW.fmtTs = function (ts) {
    if (!ts) return "—";
    const s = ts.slice(0, 19).replace("T", " ");
    if (NW.lang === "en") return s; /* déjà YYYY-MM-DD HH:mm:ss */
    /* FR : réorganise en DD/MM/YYYY HH:mm:ss */
    const [date, time] = s.split(" ");
    const [y, m, d] = date.split("-");
    return d + "/" + m + "/" + y + " " + time;
  };

  /* Applique les traductions sur tous les [data-i18n] du DOM */
  NW.applyLang = function () {
    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      const key = el.getAttribute("data-i18n");
      const t = NW.t(key);
      /* innerHTML pour les clés contenant <code> */
      if (t.includes("<")) el.innerHTML = t;
      else el.textContent = t;
    });
    /* Met à jour le bouton toggle */
    const btn = document.getElementById("lang-toggle");
    if (btn) {
      btn.querySelector(".lang-active").textContent = NW.lang.toUpperCase();
      btn.querySelector(".lang-other").textContent  = NW.lang === "fr" ? "EN" : "FR";
    }
    /* Re-formate tous les horodatages déjà rendus dans le tableau */
    document.querySelectorAll("[data-ts]").forEach(function (el) {
      const raw = el.getAttribute("data-ts");
      if (raw) el.textContent = NW.fmtTs(raw);
    });
    /* Compteur topbar rendu côté serveur */
    const countLabel = document.getElementById("alert-count-label");
    if (countLabel) {
      const v = countLabel.getAttribute("data-count-" + NW.lang);
      if (v) countLabel.textContent = v;
    }
  };

  NW.switchLang = function () {
    NW.lang = NW.lang === "fr" ? "en" : "fr";
    localStorage.setItem("nw_lang", NW.lang);
    NW.applyLang();
  };
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
      const label = s < 2 ? NW.t("just_now") : NW.t("ago", { n: s });
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
    NW.applyLang();
  });

  window.NW = NW;
})();
