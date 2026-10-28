// Test stand-in for gtag.js. Served only by the test fixture server.
window.gtag = function (cmd, id) {
  if (cmd === "config") {
    fetch("http://region1.google-analytics.com/g/collect?v=2&tid=" + id + "&en=page_view", { method: "POST", keepalive: true, mode: "no-cors" });
  }
};
