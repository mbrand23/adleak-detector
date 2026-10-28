// Test stand-in for Meta's fbevents.js. Served only by the test fixture server.
(function () {
  var ids = [];
  window.fbq = function (cmd, a) {
    if (cmd === "init") ids.push(a);
    if (cmd === "track") ids.forEach(function (id) {
      new Image().src = "http://www.facebook.com/tr?id=" + id + "&ev=" + encodeURIComponent(a) + "&noscript=1";
    });
  };
})();
