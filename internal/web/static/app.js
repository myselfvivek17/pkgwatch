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

// Live timeline. EventSource, not websockets: the flow is server-to-browser
// only, reconnection is built in, and it is about thirty lines (§8, plan M4).
(function () {
  "use strict";

  var list = document.getElementById("pw-timeline");
  if (!list || typeof EventSource === "undefined") return;

  var cursor = list.getAttribute("data-cursor") || "0";
  var source = new EventSource("/events/stream?since=" + encodeURIComponent(cursor));

  source.addEventListener("row", function (ev) {
    // Two data lines: the event's day, then its rendered HTML. The server
    // renders the row so there is exactly one definition of what a row looks
    // like, rather than a Go template and a JavaScript one drifting apart.
    var parts = ev.data.split("\n");
    var day = parts.shift();
    var html = parts.join("\n");

    var group = list.querySelector('[data-day="' + day + '"]');
    if (!group) {
      group = document.createElement("div");
      group.className = "pw-day";
      group.setAttribute("data-day", day);
      var label = document.createElement("div");
      label.className = "pw-day-label";
      label.textContent = "Today";
      group.appendChild(label);
      list.insertBefore(group, list.firstChild);
    }

    var holder = document.createElement("div");
    holder.innerHTML = html;
    var row = holder.firstElementChild;
    if (!row) return;
    // Newest first within the day, matching the server's ordering.
    var afterLabel = group.querySelector(".pw-day-label");
    group.insertBefore(row, afterLabel ? afterLabel.nextSibling : group.firstChild);
  });
})();
