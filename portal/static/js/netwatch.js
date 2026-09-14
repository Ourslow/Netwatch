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
      /* Navigation sidebar */
      "nav_supervision":   "Supervision",
      "nav_observability": "Observabilité",
      "nav_security":      "Sécurité",
      "nav_project":       "Projet & infra",
      "nav_dashboard":     "Dashboard",
      "nav_flows":         "Flux & performance",
      "nav_topology":      "Topologie",
      "nav_sla":           "SLA",
      "nav_alerts":        "Alertes IDS",
      "nav_incidents":     "Incidents",
      "nav_zeek":          "Analyse Zeek",
      "nav_graph":         "Graphe IOC",
      "nav_geomap":        "Carte GeoIP",
      "nav_audit":         "Audit réseau",
      "nav_exec":          "Dashboard Exec",
      "nav_agents":        "Agents IA",
      "nav_status":        "Statut services",
      "nav_hostgroups":    "Hostgroups",
      "nav_custom_dashboard": "Tableau personnalisé",
      "nav_applications":  "Applications",
      "nav_app_map":       "Dépendances",
      "nav_thresholds":    "Seuils",
      "live_30s":          "live 30 s",
      "vs_prev":           "vs période précédente",
      "delta_new":         "nouveau",
      /* Home observabilité */
      "dash_traffic":      "Trafic",
      "dash_traffic_sub":  "volume observé",
      "dash_alerts_24h":   "Alertes",
      "dash_critical_7d":  "critiques · 7 j",
      "dash_rtt":          "RTT moyen",
      "dash_zw_sub":       "des connexions TCP",
      "dash_services":     "Services",
      "dash_services_sub": "stack NetWatch · détail",
      "dash_volume":       "Volume réseau",
      "dash_no_flows":     "Aucun flux sur 24 h — Zeek silencieux ou Elasticsearch vide",
      "dash_listening_points": "Points d'écoute PCAP",
      "dash_top_conversations": "Top conversations (octets)",
      "dash_no_pcap":      "Aucun point d'écoute analysé — déposez un PCAP dans <code>pcaps/</code> et lancez l'analyse.",
      "dash_detail":       "Détail",
      "page_reports":      "Rapports",
      "reports_generate":  "Générer maintenant",
      "reports_col_date":  "Généré le",
      "reports_col_status": "Statut",
      "reports_col_size":  "Taille",
      "reports_empty":     "Aucun rapport généré pour le moment.",
      "page_pcap_analysis": "Analyse PCAP",
      "pcap_col_point":    "Point d'écoute",
      "pcap_col_conv":     "Conversation",
      "pcap_col_bytes":    "Octets",
      "pcap_col_duration": "Durée",
      "pcap_col_handshake": "Handshake",
      "pcap_col_retrans":  "Retrans.",
      "pcap_col_qos":      "QoS / VLAN",
      "pcap_analyze_ai":   "Analyser avec l'IA",
      "hostgroup_filter_all":   "Tous les hôtes",
      "hostgroup_import_title": "Importer des hostgroups",
      "hostgroup_import_hint": "Export CSV type NetScout — colonnes Name, Hosts, Member hostgroups...",
      "hostgroup_import_btn":  "Importer",
      "hostgroup_col_name":    "Nom",
      "hostgroup_col_desc":    "Description",
      "hostgroup_col_hosts":   "Plages",
      "hostgroup_col_members": "Sous-groupes",
      "hostgroup_col_tags":    "Tags",
      "hostgroup_empty":       "Aucun hostgroup importé pour le moment.",
      "hostgroup_clear_all":   "Tout supprimer",
      "nav_infra":         "Infrastructure",
      "nav_vms":           "Machines virtuelles",
      "nav_catalog":       "Catalogue outils",
      "nav_compare":       "Comparaison",
      "nav_compliance":    "Conformité",
      "nav_report_sec":    "Rapport",
      "nav_report":        "Rapport exécutif",
      "brand_tag":         "Observabilité réseau",
      "btn_logout":        "Déconnexion",
      /* Page titles */
      "page_dashboard":    "Dashboard",
      "page_alerts":       "Alertes IDS",
      "page_audit":        "Audit réseau",
      "page_status":       "Statut des services",
      "page_vms":          "Machines virtuelles",
      "page_compliance":   "Conformité & référentiels",
      "page_report":       "Rapport exécutif",
      /* Dashboard */
      "dash_vms_running":  "VMs actives",
      "dash_vms_stopped":  "VMs arrêtées",
      "dash_tools_oss":    "Outils open-source",
      "dash_tools_com":    "Outils commerciaux",
      "dash_last_alerts":  "Dernières alertes IDS",
      "dash_see_all":      "Voir tout",
      "dash_vms_section":  "Machines virtuelles",
      "dash_quick":        "Accès rapide",
      "dash_catalog":      "Catalogue",
      "dash_oss_link":     "Outils open-source",
      "dash_com_link":     "Outils commerciaux Axians",
      "dash_deploy_nw":    "Déployer NetWatch v2",
      "dash_deploy_so":    "Déployer Security Onion",
      "dash_no_alerts":    "Aucune alerte — Elasticsearch vide ou non joignable",
      "dash_no_vms":       "Aucune VM — Proxmox non connecté ou nœud vide",
      /* Audit */
      "audit_score":       "Score de posture réseau",
      "audit_critical":    "Critiques",
      "audit_warning":     "À corriger",
      "audit_ok":          "Conformes",
      "audit_passive":     "Audit passif, basé uniquement sur le trafic observé. Aucune sonde active ni scan intrusif.",
      "audit_es_error":    "Elasticsearch non joignable — l'audit ne peut pas évaluer les contrôles. Lancez la stack et générez du trafic.",
      "audit_no_issues":   "aucun point bloquant",
      /* Status */
      "status_up":         "Tous les services opérationnels",
      "status_up_sub":     "Stack NetWatch fonctionnelle",
      "status_deg":        "Services dégradés",
      "status_deg_sub":    "Un ou plusieurs services en anomalie",
      "status_down":       "Services indisponibles",
      "status_down_sub":   "Vérifier que la stack Docker est lancée",
      "status_internal":   "interne",
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
      /* Navigation sidebar */
      "nav_supervision":   "Monitoring",
      "nav_observability": "Observability",
      "nav_security":      "Security",
      "nav_project":       "Project & infra",
      "nav_dashboard":     "Dashboard",
      "nav_flows":         "Flows & performance",
      "nav_topology":      "Topology",
      "nav_sla":           "SLA",
      "nav_alerts":        "IDS Alerts",
      "nav_incidents":     "Incidents",
      "nav_zeek":          "Zeek Analysis",
      "nav_graph":         "IOC Graph",
      "nav_geomap":        "GeoIP Map",
      "nav_audit":         "Network Audit",
      "nav_exec":          "Exec Dashboard",
      "nav_agents":        "AI Agents",
      "nav_status":        "Services Status",
      "nav_hostgroups":    "Hostgroups",
      "nav_custom_dashboard": "Custom dashboard",
      "nav_applications":  "Applications",
      "nav_app_map":       "Dependencies",
      "nav_thresholds":    "Thresholds",
      "live_30s":          "live 30 s",
      "vs_prev":           "vs previous period",
      "delta_new":         "new",
      /* Observability home */
      "dash_traffic":      "Traffic",
      "dash_traffic_sub":  "observed volume",
      "dash_alerts_24h":   "Alerts",
      "dash_critical_7d":  "critical · 7 d",
      "dash_rtt":          "Avg RTT",
      "dash_zw_sub":       "of TCP connections",
      "dash_services":     "Services",
      "dash_services_sub": "NetWatch stack · details",
      "dash_volume":       "Network volume",
      "dash_no_flows":     "No flows in 24 h — Zeek silent or Elasticsearch empty",
      "dash_listening_points": "PCAP listening points",
      "dash_top_conversations": "Top conversations (bytes)",
      "dash_no_pcap":      "No listening point analysed — drop a PCAP in <code>pcaps/</code> and run the analysis.",
      "dash_detail":       "Details",
      "page_reports":      "Reports",
      "reports_generate":  "Generate now",
      "reports_col_date":  "Generated at",
      "reports_col_status": "Status",
      "reports_col_size":  "Size",
      "reports_empty":     "No report generated yet.",
      "page_pcap_analysis": "PCAP Analysis",
      "pcap_col_point":    "Listening point",
      "pcap_col_conv":     "Conversation",
      "pcap_col_bytes":    "Bytes",
      "pcap_col_duration": "Duration",
      "pcap_col_handshake": "Handshake",
      "pcap_col_retrans":  "Retrans.",
      "pcap_col_qos":      "QoS / VLAN",
      "pcap_analyze_ai":   "Analyze with AI",
      "hostgroup_filter_all":   "All hosts",
      "hostgroup_import_title": "Import hostgroups",
      "hostgroup_import_hint": "NetScout-style CSV export — Name, Hosts, Member hostgroups columns...",
      "hostgroup_import_btn":  "Import",
      "hostgroup_col_name":    "Name",
      "hostgroup_col_desc":    "Description",
      "hostgroup_col_hosts":   "Ranges",
      "hostgroup_col_members": "Sub-groups",
      "hostgroup_col_tags":    "Tags",
      "hostgroup_empty":       "No hostgroup imported yet.",
      "hostgroup_clear_all":   "Clear all",
      "nav_infra":         "Infrastructure",
      "nav_vms":           "Virtual Machines",
      "nav_catalog":       "Tools Catalog",
      "nav_compare":       "Comparison",
      "nav_compliance":    "Compliance",
      "nav_report_sec":    "Report",
      "nav_report":        "Executive Report",
      "brand_tag":         "Network Observability",
      "btn_logout":        "Logout",
      /* Page titles */
      "page_dashboard":    "Dashboard",
      "page_alerts":       "IDS Alerts",
      "page_audit":        "Network Audit",
      "page_status":       "Services Status",
      "page_vms":          "Virtual Machines",
      "page_compliance":   "Compliance & frameworks",
      "page_report":       "Executive Report",
      /* Dashboard */
      "dash_vms_running":  "Active VMs",
      "dash_vms_stopped":  "Stopped VMs",
      "dash_tools_oss":    "Open-source tools",
      "dash_tools_com":    "Commercial tools",
      "dash_last_alerts":  "Latest IDS alerts",
      "dash_see_all":      "View all",
      "dash_vms_section":  "Virtual Machines",
      "dash_quick":        "Quick access",
      "dash_catalog":      "Catalog",
      "dash_oss_link":     "Open-source tools",
      "dash_com_link":     "Axians commercial tools",
      "dash_deploy_nw":    "Deploy NetWatch v2",
      "dash_deploy_so":    "Deploy Security Onion",
      "dash_no_alerts":    "No alerts — Elasticsearch empty or unreachable",
      "dash_no_vms":       "No VMs — Proxmox not connected or empty node",
      /* Audit */
      "audit_score":       "Network posture score",
      "audit_critical":    "Critical",
      "audit_warning":     "To fix",
      "audit_ok":          "Compliant",
      "audit_passive":     "Passive audit, based solely on observed traffic. No active probing or intrusive scanning.",
      "audit_es_error":    "Elasticsearch unreachable — audit cannot evaluate controls. Start the stack and generate traffic.",
      "audit_no_issues":   "no blocking issues",
      /* Status */
      "status_up":         "All services operational",
      "status_up_sub":     "NetWatch stack functional",
      "status_deg":        "Degraded services",
      "status_deg_sub":    "One or more services in anomaly",
      "status_down":       "Services unavailable",
      "status_down_sub":   "Check that the Docker stack is running",
      "status_internal":   "internal",
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
    /* Compteur topbar — si le flux temps réel (SSE) l'a déjà mis à jour
       (dataset.count), retraduire cette valeur live plutôt que d'écraser
       avec l'attribut statique du rendu serveur initial. */
    const countLabel = document.getElementById("alert-count-label");
    if (countLabel) {
      if (countLabel.dataset.count !== undefined) {
        countLabel.textContent = NW.t("alerts_label", { n: parseInt(countLabel.dataset.count, 10) });
      } else {
        const v = countLabel.getAttribute("data-count-" + NW.lang);
        if (v) countLabel.textContent = v;
      }
    }
  };

  NW.switchLang = function () {
    NW.lang = NW.lang === "fr" ? "en" : "fr";
    localStorage.setItem("nw_lang", NW.lang);
    NW.applyLang();
  };

  /* ---- Thème clair / sombre ---------------------------------- */
  NW.theme = localStorage.getItem("nw_theme") || "dark";

  NW.applyTheme = function () {
    document.documentElement.setAttribute("data-bs-theme", NW.theme);
    const iconLight = document.getElementById("theme-icon-light");
    const iconDark  = document.getElementById("theme-icon-dark");
    if (iconLight && iconDark) {
      /* Icône affichée = action possible (soleil en mode sombre = « passer au clair ») */
      iconLight.style.display = NW.theme === "dark" ? "" : "none";
      iconDark.style.display  = NW.theme === "dark" ? "none" : "";
    }
  };

  NW.switchTheme = function () {
    NW.theme = NW.theme === "dark" ? "light" : "dark";
    localStorage.setItem("nw_theme", NW.theme);
    NW.applyTheme();
  };

  /* ---- Sections du menu latéral repliables -------------------- */
  NW.initNavSections = function () {
    document.querySelectorAll(".nav-section[data-bs-target]").forEach(function (trigger) {
      const targetId = trigger.getAttribute("data-bs-target").slice(1);
      const target = document.getElementById(targetId);
      if (!target) return;

      const containsActive = !!target.querySelector(".nav-link.active");
      const storageKey = "nw_navsec_" + targetId;
      let saved = null;
      try { saved = localStorage.getItem(storageKey); } catch (e) {}
      /* La section de la page active reste toujours ouverte ; sinon la
         préférence sauvegardée ; sinon data-default="closed" (section
         secondaire « Projet & infra ») ou ouvert. */
      const expanded = containsActive
        || (saved ? saved !== "closed" : trigger.getAttribute("data-default") !== "closed");

      trigger.setAttribute("aria-expanded", expanded ? "true" : "false");
      target.classList.toggle("show", expanded);

      target.addEventListener("shown.bs.collapse", function () {
        trigger.setAttribute("aria-expanded", "true");
        try { localStorage.setItem(storageKey, "open"); } catch (e) {}
      });
      target.addEventListener("hidden.bs.collapse", function () {
        trigger.setAttribute("aria-expanded", "false");
        try { localStorage.setItem(storageKey, "closed"); } catch (e) {}
      });
    });
  };
  const prefersReduced = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const ACCENT = "#22d3ee";
  const CRIT   = "#ff4d5e";

  /* ---- Thème Chart.js dérivé des tokens CSS ------------------
     Une seule source de vérité : les graphiques lisent les variables du
     design system au lieu de dupliquer des hex dans chaque page. */
  NW.cssVar = function (name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback || "";
  };
  NW.chartTheme = function () {
    const accent = NW.cssVar("--accent", ACCENT);
    return {
      accent:     accent,
      accentSoft: NW.cssVar("--accent-soft", "rgba(34,211,238,.12)"),
      crit:       NW.cssVar("--crit", CRIT),
      warn:       NW.cssVar("--med", "#f5a524"),
      ok:         NW.cssVar("--ok", "#2ee6a6"),
      grid:       NW.cssVar("--grid-line", "rgba(30,42,60,.7)"),
      tick:       NW.cssVar("--text-dim", "#57647a"),
      text:       NW.cssVar("--text-muted", "#7d8ba0"),
      bg:         NW.cssVar("--bg-base", "#0a0e16"),
      tooltip: {
        backgroundColor: NW.cssVar("--bg-elev-2", "#121b2b"),
        borderColor:     NW.cssVar("--border", "#1e2a3c"),
        borderWidth: 1,
        titleColor:      NW.cssVar("--text", "#d6e0ec"),
        bodyColor:       NW.cssVar("--text-muted", "#7d8ba0"),
        padding: 8,
      },
      /* Palette catégorielle (donuts, barres) */
      palette: [
        "rgba(34,211,238,.8)",  "rgba(94,231,251,.75)",  "rgba(56,189,248,.75)",
        "rgba(129,140,248,.75)","rgba(167,139,250,.75)", "rgba(232,121,249,.75)",
        "rgba(251,191,36,.8)",  "rgba(52,211,153,.75)",  "rgba(248,113,113,.8)",
        "rgba(251,146,60,.75)",
      ],
    };
  };
  /* Défauts globaux Chart.js (police, couleurs) — appliqués une fois */
  if (typeof Chart !== "undefined") {
    Chart.defaults.font.family = NW.cssVar("--font-ui", "Inter, sans-serif");
    Chart.defaults.color = NW.cssVar("--text-muted", "#7d8ba0");
    Chart.defaults.borderColor = NW.cssVar("--grid-line", "rgba(30,42,60,.7)");
  }

  /* Tendance vs période précédente → HTML d'une .kpi-delta.
     cur/prev : valeurs ; opts.good = true si une hausse est souhaitable. */
  NW.deltaHtml = function (cur, prev, opts) {
    opts = opts || {};
    cur = Number(cur) || 0; prev = Number(prev) || 0;
    var ref = '<span class="kpi-delta-ref">' + NW.t("vs_prev") + '</span>';
    if (!prev && !cur) return '<span class="kpi-delta flat">— ' + ref + '</span>';
    if (!prev) return '<span class="kpi-delta flat">' + NW.t("delta_new") + ' ' + ref + '</span>';
    var pct = Math.round((cur - prev) / prev * 100);
    if (Math.abs(pct) < 1) return '<span class="kpi-delta flat"><i class="bi bi-dash"></i>0 % ' + ref + '</span>';
    var dir = pct > 0 ? 'up' : 'down';
    var icon = pct > 0 ? 'bi-arrow-up-right' : 'bi-arrow-down-right';
    return '<span class="kpi-delta ' + dir + (opts.good ? ' good' : '') + '"><i class="bi ' + icon + '"></i>'
      + (pct > 0 ? '+' : '') + pct + ' % ' + ref + '</span>';
  };
  NW.applyDeltas = function (root) {
    (root || document).querySelectorAll("[data-delta-cur]").forEach(function (el) {
      el.innerHTML = NW.deltaHtml(el.getAttribute("data-delta-cur"), el.getAttribute("data-delta-prev"),
                                  { good: el.hasAttribute("data-delta-good") });
    });
  };

  /* Octets → unité lisible (partagé par toutes les pages) */
  NW.fmtBytes = function (b) {
    b = Number(b) || 0;
    if (b === 0) return "0 B";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(i === 0 ? 0 : 1) + " " + u[i];
  };

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
        plugins: { legend: { display: false }, tooltip: opts.tooltip === false ? { enabled: false } : Object.assign({}, NW.chartTheme().tooltip, {
          displayColors: false,
          callbacks: { title: function () { return ""; },
            label: function (c) { return c.parsed.y + " " + NW.t("spark_tooltip"); } },
        }) },
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
    NW.applyTheme();
    NW.initNavSections();
    NW.applyDeltas();
  });

  window.NW = NW;
})();
