// Applies the colour theme chosen on the Settings page before the page is drawn, so there is no flash
// of the wrong colours. The choice is kept in this browser only; "system" (no value) follows the
// operating system.
(function () {
  try {
    var t = localStorage.getItem('certsmith.theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* no storage: follow the system */ }
})();
