// Hand-written, no dependencies. pkgwatch watches for supply-chain attacks;
// pulling a framework in to toggle a class would be a self-own (§8).
(function () {
  "use strict";

  var KEY = "pkgwatch-theme";
  var root = document.documentElement;

  function apply(theme) {
    if (theme === "light") {
      root.setAttribute("data-theme", "light");
    } else {
      root.removeAttribute("data-theme");
    }
  }

  // The inline script in <head> has already applied the stored theme so the
  // page never flashes the wrong one. This only handles the toggle.
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-theme-toggle]");
    if (!btn) return;
    var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    apply(next);
    try {
      localStorage.setItem(KEY, next);
    } catch (e) {
      /* private mode — the toggle still works for this page load */
    }
  });
})();
