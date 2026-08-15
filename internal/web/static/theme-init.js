// Applies the saved theme before first paint, so the page never flashes the
// wrong one.
//
// A file rather than an inline <script> so the Content-Security-Policy can say
// script-src 'self' with no 'unsafe-inline'. Inline script is the thing CSP is
// mostly there to stop, and keeping four lines inline would have bought that
// exemption for every page. Loaded synchronously in <head>, which still runs
// before the body renders — the flash it prevents is why it exists.
try {
  if (localStorage.getItem("pkgwatch-theme") === "light") {
    document.documentElement.setAttribute("data-theme", "light");
  }
} catch (e) {}
