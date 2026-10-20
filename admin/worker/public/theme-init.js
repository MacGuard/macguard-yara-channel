/* Runs before first paint (blocking, external because the CSP forbids inline script): applies a forced theme so there is no flash. Auto = follow the system. */
(function () { try { var v = localStorage.getItem('mg_theme'); if (v === 'light' || v === 'dark') document.documentElement.setAttribute('data-theme', v); } catch (e) { /* storage may be unavailable */ } })();
