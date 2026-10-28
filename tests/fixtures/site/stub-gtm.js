// Test stand-in for gtm.js. Served only by the test fixture server.
window.google_tag_manager = window.google_tag_manager || {};
window.google_tag_manager["GTM-TEST1"] = { dataLayer: {} };
window.dataLayer = window.dataLayer || [];
window.dataLayer.push({ event: "gtm.js" });
