// NetWatch — site produit : onglets captures, menu mobile, apparition au défilement. Aucune dépendance.
(function () {
  "use strict";

  // Onglets captures d'écran
  var tabs = document.querySelectorAll(".tabs [role=tab]");
  var panels = document.querySelectorAll(".panel");
  function select(id) {
    tabs.forEach(function (t) { t.setAttribute("aria-selected", t.getAttribute("aria-controls") === id ? "true" : "false"); });
    panels.forEach(function (p) { p.classList.toggle("active", p.id === id); });
  }
  tabs.forEach(function (t) {
    t.addEventListener("click", function () { select(t.getAttribute("aria-controls")); });
    t.addEventListener("keydown", function (e) {
      var i = Array.prototype.indexOf.call(tabs, t), n = tabs.length;
      if (e.key === "ArrowRight") { tabs[(i + 1) % n].focus(); tabs[(i + 1) % n].click(); }
      if (e.key === "ArrowLeft") { tabs[(i - 1 + n) % n].focus(); tabs[(i - 1 + n) % n].click(); }
    });
  });

  // Menu mobile
  var burger = document.querySelector(".burger"), menu = document.querySelector(".nav ul");
  if (burger && menu) {
    burger.addEventListener("click", function () {
      var open = menu.classList.toggle("open");
      burger.setAttribute("aria-expanded", open ? "true" : "false");
    });
    menu.addEventListener("click", function (e) { if (e.target.tagName === "A") menu.classList.remove("open"); });
  }

  // Apparition au défilement
  if ("IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    document.querySelectorAll(".rv").forEach(function (el) { io.observe(el); });
  } else {
    document.querySelectorAll(".rv").forEach(function (el) { el.classList.add("in"); });
  }

  // Copie de la commande d'installation
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var txt = document.querySelector(btn.getAttribute("data-copy")).innerText;
      if (navigator.clipboard) navigator.clipboard.writeText(txt).then(function () {
        var old = btn.textContent; btn.textContent = "Copié !"; setTimeout(function () { btn.textContent = old; }, 1600);
      });
    });
  });
})();
